"""Regression coverage for customer list/identity boundary findings."""
import json
import pytest
import requests_mock
# Match pytest's package namespace in git-archive snapshots as well as worktrees.
if __package__:
    from .test_connector import (
        APP_ERROR, APP_SUCCESS, IDENTITY, ORG, build_metadata,
        config_check_output, dispatch_flow, job_output_url, make_connector, patch_ar,
    )
    from .test_quarantine_modes import selected
else:
    from test_connector import (
        APP_ERROR, APP_SUCCESS, IDENTITY, ORG, build_metadata,
        config_check_output, dispatch_flow, job_output_url, make_connector, patch_ar,
    )
    from test_quarantine_modes import selected

MODES = ['release_requested', 'needs_review']

def envelope(mode, output):
    value = {**output, **build_metadata()}
    return selected(value) if mode == 'needs_review' else value

def row(mode, **changes):
    return {'Identity': IDENTITY,
            'ReleaseStatus': 'NotReleased' if mode == 'needs_review' else 'Requested',
            **changes}

def flow(mode, rows, **changes):
    return {'config_check': envelope(mode, config_check_output()),
            'list': envelope(mode, {'action': 'list', 'count': len(rows),
                                    'messages': rows, **changes})}

def connector(mode, **config):
    return make_connector(config_overrides={'quarantine_selection_mode': mode,
                                           'exchange_organization': ORG, **config})

@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('identity', [None, {}, [], ['not-a-guid'], True, 23, '', 'bad', IDENTITY+'\n'])
def test_invalid_list_identity_fails_without_partial_results(mode, identity):
    c = connector(mode); ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        bodies = dispatch_flow(m, flow(mode, [row(mode), row(mode, Identity=identity)]))
        assert c._handle_list_quarantine_requests({}) == APP_ERROR
        assert ar.get_data() == []
        assert 'identity' in ar.get_message().lower()
        assert all(b['action'] not in ('export', 'release', 'deny') for b in bodies)

@pytest.mark.parametrize('handler', ['_handle_get_quarantine_message',
                                    '_handle_release_quarantine_message',
                                    '_handle_deny_quarantine_release'])
@pytest.mark.parametrize('identity', [None, {}, [], ['not-a-guid'], True, 23])
def test_direct_identity_type_rejected_without_any_http(handler, identity):
    c = connector('release_requested'); ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        assert getattr(c, handler)({'identity': identity}) == APP_ERROR
        assert 'identity' in ar.get_message().lower()
        assert ar.get_data() == []
        assert m.call_count == 0

@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('count', [True, False, 1.9, 1.0, float('inf'), '1.9', {}, []])
def test_noninteger_backend_count_rejected(mode, count):
    c = connector(mode); ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        dispatch_flow(m, flow(mode, [row(mode)], count=count))
        assert c._handle_list_quarantine_requests({}) == APP_ERROR
        assert ar.get_data() == []
        assert 'count' in ar.get_message()

@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('limit', [True, False, 1.9, 1.0, float('inf'), '1.9', {}, [], 0, -1, 1001])
def test_noninteger_or_out_of_range_limit_rejected_before_http(mode, limit):
    c = connector(mode); ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        assert c._handle_list_quarantine_requests({'max_results': limit}) == APP_ERROR
        assert 'max_results' in ar.get_message()
        assert ar.get_data() == []
        assert m.call_count == 0

@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('limit', [None, 1, '1', 1000])
def test_backend_overreturn_is_locally_capped(mode, limit):
    c = connector(mode); ar = patch_ar(c)
    effective = int(limit) if limit is not None else 2
    rows = [row(mode, Identity=f'{index:08x}'+IDENTITY[8:]) for index in range(effective+1)]
    with requests_mock.Mocker() as m:
        bodies = dispatch_flow(m, flow(mode, rows))
        params = {} if limit is None else {'max_results': limit}
        assert c._handle_list_quarantine_requests(params) == APP_SUCCESS, ar.get_message()
        assert len(ar.get_data()) == effective
        assert ar.get_data() == [dict(r, SenderAddress='', RecipientAddress='', Subject='',
                                     Type='', ReceivedTime='', Expires='', PolicyName='')
                                 for r in rows[:effective]]
        assert ar.get_summary() == {'total_found': effective, 'max_results': effective,
                                    'results_may_be_truncated': True}
        assert len([b for b in bodies if b['action']=='list']) == 1

@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('count', [1, '1', ' 1 ', '+1'])
def test_integer_count_compatibility(mode, count):
    c = connector(mode); ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        dispatch_flow(m, flow(mode, [row(mode)], count=count))
        assert c._handle_list_quarantine_requests({'max_results': '1'}) == APP_SUCCESS, ar.get_message()
        assert ar.get_data()[0]['Identity'] == IDENTITY

@pytest.mark.parametrize('mode', MODES)
def test_poll_validates_entire_list_before_any_container(mode):
    c = connector(mode); ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        dispatch_flow(m, flow(mode, [row(mode), row(mode, Identity=None)]))
        assert c._handle_on_poll({}) == APP_ERROR
        assert c._saved_containers == []
        assert ar.get_data() == []

@pytest.mark.parametrize('mode', MODES)
def test_missing_list_identity_is_protocol_error(mode):
    c = connector(mode); ar = patch_ar(c)
    missing = row(mode); missing.pop('Identity')
    with requests_mock.Mocker() as m:
        dispatch_flow(m, flow(mode, [missing]))
        assert c._handle_list_quarantine_requests({}) == APP_ERROR
        assert ar.get_data() == []

@pytest.mark.parametrize('mode', MODES)
def test_legacy_single_row_still_rejects_noninteger_count(mode):
    c = connector(mode); ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        dispatch_flow(m, flow(mode, [], messages=row(mode), count=True))
        assert c._handle_list_quarantine_requests({}) == APP_ERROR
        assert ar.get_data() == []

@pytest.mark.parametrize('mode', MODES)
def test_poll_caps_backend_overreturn_to_fixed_first_page(mode):
    c = connector(mode); ar = patch_ar(c)
    rows = [row(mode, Identity=f'{index:08x}'+IDENTITY[8:]) for index in range(51)]
    seen = []
    def reserve(messages, capacity, per_poll):
        seen.extend(messages)
    c._ingest_reserve = reserve
    with requests_mock.Mocker() as m:
        bodies = dispatch_flow(m, flow(mode, rows))
        assert c._handle_on_poll({}) == APP_SUCCESS, ar.get_message()
        assert [r['Identity'] for r in seen] == [r['Identity'] for r in rows[:50]]
        assert bodies[-1]['page_size'] == 50
        assert c._saved_containers == []


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('count', [True, 1.9, 1.0, float('inf'), '1.9'])
def test_chunked_list_count_is_not_lossily_coerced(mode, count):
    c = connector(mode); ar = patch_ar(c)
    records = [envelope(mode, {'action': 'list', 'mode': 'list_chunk',
                               'chunk_index': 0, 'messages': [row(mode)]}),
               envelope(mode, {'action': 'list', 'mode': 'list_complete',
                               'chunk_count': 1, 'count': count})]
    raw = '\n'.join(json.dumps(record) for record in records)
    with requests_mock.Mocker() as m:
        bodies = dispatch_flow(m, flow(mode, []))
        def output(request, context):
            if bodies[-1]['action'] == 'config_check':
                return json.dumps(envelope(mode, config_check_output()))
            return raw
        m.get(job_output_url(), text=output)
        assert c._handle_list_quarantine_requests({}) == APP_ERROR
        assert 'count' in ar.get_message()
        assert ar.get_data() == []
