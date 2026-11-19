# Runbook troubleshooting

Use companion Runbook 3.7.4 with App 3.7.4. Deploy it separately to Azure
Automation. Compare the runbook version and source fingerprint in the job
result with the file you deployed when investigating an unexpected response.
Exchange authentication uses the Automation Account's Managed Identity.

## Bounded disposition diagnostics

Since Runbook 3.4.5, the runbook redacts optional warning/information/verbose streams before bounding each to 2,048 characters. Each `cmdlet_<stream>` has `<field>_original_chars` (redacted source length) and `<field>_truncated` evidence. Structured freeform error targets are also redacted before truncation. Full errors retain their existing chunked error transport; a truncated optional diagnostic is not a failed disposition. Compare actual terminal status and postcondition evidence.

## Exchange sign-in evidence

Every Release/Deny/diagnose result states the effective, non-secret sign-in:
`exchange_auth_method` (always `ManagedIdentity`; source `webhook`, or `default`
when no method was sent) and `exchange_organization` (+`_source`: `webhook` for
the asset field, `automation_variable` for the `ExchangeOrganization`
variable). There are no credential fields; a result carrying
`exchange_credential_name` or `exchange_credential_source` does not satisfy the current
Managed Identity-only contract and the app rejects it. Exchange authentication does not use a stored username/password credential.

An explicit `auth_method` other than exactly `ManagedIdentity`
(`invalid_exchange_auth_method`) and any `credential_name`
(`unsupported_credential_name`) are rejected up front, before module import,
sign-in, message access or release/deny. A blank method means Managed Identity.
`exchange_connection_metadata` is best-effort passive evidence and never blocks
a disposition. The read-only action `config_check` (run by the app before the
first release/deny of an asset instance) returns the same fields with
`config_contract=exchange_connection_v1` and makes no Exchange connection.

## Release and Deny: one workflow, two explicit commands

Both actions enter `Invoke-RequestedDisposition` and follow these steps:

1. `Get-QuarantineMessage` must confirm the exact identity and Microsoft
   status `Requested`.
   An already matching terminal state is idempotent (zero writes); any other
   state stops. No metadata or RBAC query precedes the write.
2. `Invoke-QuarantineDisposition` performs the only write, exactly once, with
   no retry. Release uses `Release-QuarantineMessage -Identity <id>
   -ReleaseToAll -Confirm:$false -ErrorAction Stop`; Deny uses
   `Release-QuarantineMessage -Identity <id> -ReleaseToAll -ActionType Deny
   -Confirm:$false -ErrorAction Stop`. Warning, information, verbose and error
   streams are captured. The real ID is passed through singular `Identity`;
   no dummy or plural `Identities` is sent. Both operations select all recipients;
   Deny explicitly adds `ActionType Deny`. The observed ExchangeOnlineManagement
   3.5.0 parameter metadata permits this combination in `OrgReleaseToAll`.
   Offline tests verify invocation and protocol, not Exchange acceptance.
   Expanded read-only proxy diagnostics
   remain available through `diagnose`.
   Install the paired app update before deploying this runbook. It accepts
   `identity_releasetoall_actiontype_deny` with exact Identity/ReleaseToAll/ActionType
   argument evidence and retains all three earlier Deny contracts for readback.
   Earlier apps reject the new contract. Release is unchanged.
3. `Wait-QuarantinePostcondition` reads Exchange again, also after a cmdlet
   failure. Only the matching terminal state (`Released` or `Denied`) proves
   success. A cmdlet error can coexist with confirmed success. An unconfirmed
   outcome requires `reconcile` before considering any retry.
4. The Exchange session is disconnected exactly once; the outcome is recorded
   in `exchange_disconnect_status`/`exchange_disconnect_error` and never alters
   the disposition result.

Only exact Microsoft `Released`/`Denied` observations free an intake slot,
not playbook completion. `NotReleased` is an observed status, not an intake option.

Independent result fields: `cmdlet_invocation_attempted` (a call was made),
`cmdlet_executed` (the cmdlet ran to a native outcome), `cmdlet_error` with
`cmdlet_fully_qualified_error_id`, `cmdlet_exception_type`,
`cmdlet_error_category`, `cmdlet_error_position`, `cmdlet_script_stack_trace`,
request/correlation IDs, plus `precondition_trace`, `postcondition_trace`,
`observed_release_status_history` and `handling`. A genuine binder or
command-not-found error has `cmdlet_invocation_attempted=true` and
`cmdlet_executed=false`.

| `error_code` | Meaning / next step |
| --- | --- |
| `precondition_unconfirmed` | No write; inspect exact identity and current status. |
| `disposition_rejected` | Deterministic rejection; inspect native cmdlet error. |
| `postcondition_unconfirmed` | Write may have happened; run read-only reconcile before retry. |
| `exchange_connection_failed` | Sign-in failed before any write; the native error is returned without credential values. |
| `automation_variable_empty` | No organization (asset field or `ExchangeOrganization` variable). |
| `invalid_exchange_auth_method` | A caller sent an auth method other than `ManagedIdentity` (for example `Credential`); nothing was connected or read. |
| `unsupported_credential_name` | A caller sent `credential_name`; credential sign-in no longer exists. |

## Module metadata

After `Import-Module` succeeds the runbook reads the loaded module version and
path as passive evidence. A failure there is ignored (version `unknown`) and
never blocks the sign-in or disposition (only a fixed verbose notice is
written, never the lookup's error text); a failing `Import-Module`
(`module_import_failed`) or `Connect-ExchangeOnline`
(`exchange_connection_failed`) is a real error and is returned unchanged.

## Collecting diagnostic information

Record the app/runbook versions, Azure job ID, selected message identity and
sanitized error fields. Use **inspect release environment** for read-only
identity/runtime details. Enable its optional RBAC diagnostics only when you
need tenant permission information. Verify uncertain Release/Deny results
with **reconcile quarantine operation** before considering another write.

For intake status, recovery and artifact fields, see
[Email import and recovery](ingestion.md).

## Collect loaded Exchange proxy evidence without tenant shell access

Use the paired diagnostic hotfix app and runbook, then run **inspect release
environment** in SOAR with the exact quarantine identity. Leave `include_rbac`
false unless tenant-wide RBAC inspection is separately requested. The customer
only needs to replace/publish the runbook; no interactive tenant session is
required by the operator. No Release/Deny cmdlet or captured source is executed.

The action returns `cmdlet_proxy_diagnostics` (JSON string) and
`cmdlet_proxy_diagnostics_status` in data/summary. The JSON contains ActionType's
actual type, enum names/numeric values and ValidateSet; loaded proxy source and
same-module Execute-Command / CheckRetryAndHandleWaitTime source, hashes and
line-numbered forwarding excerpts. Source is redacted before output. Per command,
source is capped at 32768 characters, excerpts at 16384 and excerpt lines at 512.
Missing helpers, compiled commands and truncation are explicit; `partial` is not
proof of a complete transport trace. `request_capture=false` means these are
static definitions, not the actual outgoing HTTP request. No live variables,
access tokens or headers are collected. Release, Deny and reconciliation paths
are unchanged by this diagnostic addition. Older runbooks remain compatible
and show `not_available` in the new app summary.
