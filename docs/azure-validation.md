# Azure Automation sandbox validation

This runbook handles complete quarantined EML files in an Azure Automation
Cloud Sandbox with a documented 400 MB memory limit. Local transport tests do
not include the ExchangeOnlineManagement module, Exchange remoting, or the
deserialised `Export-QuarantineMessage` result. They cannot establish a safe
production cap by themselves.

The repository therefore uses a conservative 24 MiB decoded cap until the
following validation is completed in a non-production Automation Account.

## Required environment

- The exact candidate app/runbook hashes; paired Runbook 3.7.4,
  imported and published only in the approved test account; use release-kit
  checksums and executable version/fingerprints.
- The exact production-intended PowerShell runtime and ExchangeOnlineManagement
  module pair, recorded from the actual Azure job; no PowerShell 7.2 mandate.
  Exchange sign-in is Managed Identity only (the app polling identity is separate).
- An App Registration with only the documented Automation job permissions.
- Quarantined fixtures near these decoded EML sizes:
  - 24,602,271 bytes (known production case);
  - exactly 25,165,824 bytes (24 MiB cap);
  - 25,165,825 bytes (cap plus one);
  - a smaller chunked control fixture.

Do not perform this validation in production and do not release or deny any
fixture. Use only the internal read-only runbook `export` operation under the approved
test procedure; the public app Get/export action is removed. For email import
fixtures, disable downstream automation and keep all mail quarantined; capture
the native poll and container/Vault evidence rather than a legacy ActionResult.

## Evidence to capture

For every run, record:

- runbook and app versions plus Git commit;
- Azure Automation job ID and terminal status;
- queue, start, and completion timestamps;
- decoded EML size, base64 length, chunk count, and SHA-256;
- peak process working set if available through a temporary diagnostic copy of
  the runbook or the platform's supported metrics;
- whether the job produced one complete structured result;
- original/attachment Vault downloads, byte counts and matching hashes;
- native poll status, exact container/artifact IDs and bounded ledger reason
  for blocked mail; internal export envelope evidence where tested directly.

Email import always uses Vault and selected metadata; legacy `export_mode` and
`create_email_artifacts` settings do not disable them. Submission acceptance in
a separate positive native-chain test is not downstream execution evidence.

Never paste webhook URLs, OAuth tokens, credentials, full EML content, or
message bodies into issue evidence.

## Required cases

### 1. Known production-sized EML

Expected:

- decoded size 24,602,271 bytes;
- 129 chunks at 256,000 base64 characters per chunk;
- job `Completed`;
- connector SHA-256 matches the source fixture;
- Native original-mail Vault import and download succeed with matching hashes.

### 2. Exact 24 MiB boundary

Expected:

- decoded size 25,165,824 bytes;
- 132 chunks;
- job `Completed`;
- SHA-256 and reassembled size match;
- measured peak memory leaves a documented safety reserve below 400 MB.

One successful run is not sufficient. Repeat with cold and warm module starts.

### 3. Cap plus one byte

Expected:

- decoded size 25,165,825 bytes;
- structured `error_code=export_oversized`;
- `handling=fail_closed`;
- `max_decoded_size=25165824`;
- no Vault import;
- native identity remains blocked and holds its slot; no downstream analysis,
  release/deny, or automatic preparation retry.

### 4. Failure controls

Exercise a failed or suspended job without valid structured output. The app
must report a transport/job failure and must not classify it as oversized.

## Decision rule

Keep 24 MiB only if repeated exact-boundary exports, including cold module
starts, stay below the 400 MB sandbox limit with an explicitly documented
reserve. If they do not, record the failure and propose a separately approved lower cap or
Hybrid Runbook Worker/large-file transport solution. Neither is a supported
operator switch that bypasses the current app cap. Do not raise the cap based on local transport
measurements.

Attach the sanitized evidence to issue #18 and cross-reference #17 for the
structured error/job-state result. Treat this validation as incomplete until current candidate evidence is
attached; prior issue status or offline tests do not prove it. The full positive
native Mail → container → Vault → automation/ES chain remains separately
unverified; see [native ingestion](ingestion.md) for deployment-test prerequisites.
