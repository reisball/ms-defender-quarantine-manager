"""
Single-email SAA example for MS Quarantine main 1832021. Below 30: release; 30-100: native analyst prompt. Errors or unanswered prompts leave the event unchanged. Close only after successful quarantine action. Inactive template; map assets and approver before use.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'submit_email' block
    submit_email(container=container)

    return

@phantom.playbook_block()
def submit_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("submit_email() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.vaultId","artifact:*.id"])

    parameters = []

    # build parameters list for 'submit_email' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "file": container_artifact_item[0],
                "user_agent": "Default",
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate file", parameters=parameters, name="submit_email", assets=["configure_saa_asset"], callback=submission_succeeded)

    return


@phantom.playbook_block()
def submission_succeeded(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("submission_succeeded() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["submit_email:action_result.status", "==", "success"],
            ["submit_email:action_result.data.*.JobID", "!=", None],
            ["submit_email:action_result.data.*.JobID", "!=", ""]
        ],
        conditions_dps=[
            ["submit_email:action_result.status", "==", "success"],
            ["submit_email:action_result.data.*.JobID", "!=", None],
            ["submit_email:action_result.data.*.JobID", "!=", ""]
        ],
        name="submission_succeeded:condition_1",
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        get_summary(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def get_summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_summary() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    submit_email_result_data = phantom.collect2(container=container, datapath=["submit_email:action_result.data.*.JobID","submit_email:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_summary' call
    for submit_email_result_item in submit_email_result_data:
        if submit_email_result_item[0] is not None:
            parameters.append({
                "job_id": submit_email_result_item[0],
                "timeout": 30,
                "context": {'artifact_id': submit_email_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get job summary", parameters=parameters, name="get_summary", assets=["configure_saa_asset"], callback=score_policy)

    return


@phantom.playbook_block()
def score_policy(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("score_policy() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["get_summary:action_result.status", "==", "success"],
            ["get_summary:action_result.summary.Score", "!=", None],
            ["get_summary:action_result.summary.Score", "!=", ""],
            ["get_summary:action_result.summary.Score", ">=", 0],
            ["get_summary:action_result.summary.Score", "<=", 100],
            ["get_summary:action_result.summary.Score", "<", 30]
        ],
        conditions_dps=[
            ["get_summary:action_result.status", "==", "success"],
            ["get_summary:action_result.summary.Score", "!=", None],
            ["get_summary:action_result.summary.Score", "!=", ""],
            ["get_summary:action_result.summary.Score", ">=", 0],
            ["get_summary:action_result.summary.Score", "<=", 100],
            ["get_summary:action_result.summary.Score", "<", 30]
        ],
        name="score_policy:condition_1",
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        join_release_email(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["get_summary:action_result.status", "==", "success"],
            ["get_summary:action_result.summary.Score", "!=", None],
            ["get_summary:action_result.summary.Score", "!=", ""],
            ["get_summary:action_result.summary.Score", ">=", 0],
            ["get_summary:action_result.summary.Score", "<=", 100],
            ["get_summary:action_result.summary.Score", ">=", 30]
        ],
        conditions_dps=[
            ["get_summary:action_result.status", "==", "success"],
            ["get_summary:action_result.summary.Score", "!=", None],
            ["get_summary:action_result.summary.Score", "!=", ""],
            ["get_summary:action_result.summary.Score", ">=", 0],
            ["get_summary:action_result.summary.Score", "<=", 100],
            ["get_summary:action_result.summary.Score", ">=", 30]
        ],
        name="score_policy:condition_2",
        delimiter=",")

    # call connected blocks if condition 2 matched
    if found_match_2:
        review_email(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def review_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("review_email() called")

    # set approver and message variables for phantom.prompt call

    user = "configure_approver"
    role = None
    message = """Review this quarantined email.\n\nFrom: {0}\nTo: {1}\nSubject: {2}\nQuarantine identity: {3}\nSAA score: {4}\nSAA report: {5}\n\nRelease the email? Yes releases it; No denies the release request."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.senderAddress",
        "artifact:*.cef.recipientAddress",
        "container:name",
        "container:data.quarantine_identity",
        "get_summary:action_result.summary.Score",
        "get_summary:action_result.summary.AppURL"
    ]

    # responses
    response_types = [
        {
            "prompt": "Release this email?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=1440, name="review_email", parameters=parameters, response_types=response_types, callback=analyst_choice)

    return


@phantom.playbook_block()
def analyst_choice(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("analyst_choice() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["review_email:action_result.status", "==", "success"],
            ["review_email:action_result.summary.responses.0", "==", "Yes"]
        ],
        conditions_dps=[
            ["review_email:action_result.status", "==", "success"],
            ["review_email:action_result.summary.responses.0", "==", "Yes"]
        ],
        name="analyst_choice:condition_1",
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        join_release_email(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["review_email:action_result.status", "==", "success"],
            ["review_email:action_result.summary.responses.0", "==", "No"]
        ],
        conditions_dps=[
            ["review_email:action_result.status", "==", "success"],
            ["review_email:action_result.summary.responses.0", "==", "No"]
        ],
        name="analyst_choice:condition_2",
        delimiter=",")

    # call connected blocks if condition 2 matched
    if found_match_2:
        deny_email(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def join_release_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_release_email() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_release_email_called"):
        return

    if phantom.completed(action_names=["get_summary"]):
        # save the state that the joined function has now been called
        phantom.save_block_result(key="join_release_email_called", value="release_email")

        # call connected block "release_email"
        release_email(container=container, handle=handle)

    return


@phantom.playbook_block()
def release_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("release_email() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    data_quarantine_identity_value = container.get("data", {}).get("quarantine_identity", None)

    parameters = []

    if data_quarantine_identity_value is not None:
        parameters.append({
            "identity": data_quarantine_identity_value,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("release quarantine message", parameters=parameters, name="release_email", assets=["configure_quarantine_asset"], callback=release_succeeded)

    return


@phantom.playbook_block()
def deny_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("deny_email() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    data_quarantine_identity_value = container.get("data", {}).get("quarantine_identity", None)

    parameters = []

    if data_quarantine_identity_value is not None:
        parameters.append({
            "identity": data_quarantine_identity_value,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("deny quarantine release", parameters=parameters, name="deny_email", assets=["configure_quarantine_asset"], callback=deny_succeeded)

    return


@phantom.playbook_block()
def release_succeeded(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("release_succeeded() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["release_email:action_result.status", "==", "success"]
        ],
        conditions_dps=[
            ["release_email:action_result.status", "==", "success"]
        ],
        name="release_succeeded:condition_1",
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        join_close_event(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def deny_succeeded(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("deny_succeeded() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["deny_email:action_result.status", "==", "success"]
        ],
        conditions_dps=[
            ["deny_email:action_result.status", "==", "success"]
        ],
        name="deny_succeeded:condition_1",
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        join_close_event(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def join_close_event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_close_event() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_close_event_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_block_result(key="join_close_event_called", value="close_event")

    # call connected block "close_event"
    close_event(container=container, handle=handle)

    return


@phantom.playbook_block()
def close_event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("close_event() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="closed")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return
