# Email import and recovery

## Configure intake

Configure the schedule and container label in native **Ingest Settings**, or use **Poll Now** for a manual import. Disable the schedule to pause automatic imports. The app has no additional ingestion-enable checkbox. Azure job polling settings monitor individual jobs, not the ingestion schedule.

Use one ingesting asset per tenant. Its state and locks are asset-specific; separate assets can admit the same source message. Select the tenant, Exchange organization, source mode and target before starting. Changing that scope while state exists is rejected. Do not delete state to bypass the check.

Native email import requires authenticated local SOAR REST access. Automation Broker is unsupported; SOAR Cloud compatibility has not been verified. The optional `es_soar_base_url` overrides the trusted HTTPS endpoint for both SOAR and ES import. Native runtime authentication may supply its own URL. Azure TLS verification remains enforced independently of the SOAR platform's local transport policy.

| Selection | Microsoft source status |
|---|---|
| `release_requested` (default) | `Requested` |
| `needs_review` | `NotReleased` |

`needs_review` includes mail without a recipient release request. Check tenant eligibility before attempting Deny for that status.

## Active-message window

`on_poll_max_containers` sets the maximum number of unresolved Microsoft identities: default 10, range 1–50. Reservations and partially prepared messages count toward the limit. Poll Now's `container_count` can restrict new admissions further but cannot exceed the asset ceiling.

The app reads tracked Microsoft statuses and frees slots only after observing exact `Released` or `Denied` results. Analysis completion, an import error, a missing identity or an intermediate status does not free a slot. Missing or expired mail therefore needs investigation rather than automatic replay.

Free slots are filled from the first 50 candidates matching the source status. There is no pagination or stable ordering guarantee. An empty import is not proof of an empty backlog. Existing pending work is processed before discovering more mail.

## Preparation and automation

For each admitted message, the app:

1. Exports and validates the original EML.
2. Creates a dedicated container with automation disabled.
3. Saves the original EML, attachments and selected mail metadata.
4. Publishes the completed message to the configured target.

Preparation retries reuse recorded container/file references. A deterministic MIME or size defect blocks that message instead of publishing an incomplete email. Tracked state survives connector restarts.

For SOAR's **combined** layout, saving the single complete email artifact with native `run_automation=true` enables automation. The parameter belongs to the artifact save, outside `cef`. Configure the intended active playbook and container routing label. The app saves the container with automation disabled and completes every Vault upload before this final save. It does not publish a separate readiness marker or repeat import checks in the playbook.

For ES, native ES threat-analysis and automation settings control downstream processing. Publication acceptance is not evidence that analysis or a playbook completed.

### Data available to SOAR playbooks (combined layout)

Each new message has **one event and one email artifact**, even when all optional fields are disabled or missing. The artifact is named after the email subject (`No subject` if absent); the event uses the subject with `[No subject]` as its fallback. Field selections control artifact content, not its name.

| Required input | Native data path | Source |
|---|---|---|
| Original email for SAA/ANY.RUN | `artifact:*.cef.vaultId` | Vault reference to the original EML, never an attachment |
| Sender for the approval prompt | `artifact:*.cef.senderAddress` | Microsoft's quarantine-list `SenderAddress` |
| Recipient for the approval prompt | `artifact:*.cef.recipientAddress` | Microsoft's quarantine-list `RecipientAddress` |
| Release/Deny identity and prompt context | `container:data.quarantine_identity` | Microsoft quarantine identity |
| Prompt subject | `container:name` | Event subject |

The three artifact fields are always populated by the app and have no selection controls. Old false checkbox values do not suppress them. RFC Sender or delivery headers do not replace Microsoft's sender/recipient values. Optional From/To and other header fields retain their existing meanings and selections. An unavailable optional header is omitted, without preventing the required artifact from being saved.

There are no separate Request, Original-EML, Ready, technical, or per-attachment email artifacts in this layout. Internal work-item state and `ingestionReady` are not added as CEF fields. Identity and subject remain available from the event regardless of optional display settings.

The original EML and attachments remain in the event's Vault. Platform-generated file metadata is not an extra app email artifact. Inline attachments and attached EML messages are included. Duplicate filenames receive stable prefixes; path components and control characters are removed. The original Vault EML is authoritative.

### Other paths and existing events

The separate-field SOAR layout, ES ingestion, and standalone export actions retain their existing behavior. The separate-field layout still uses its Request, file, selected-field and final Ready artifacts. Legacy field selections stored on an asset remain readable by those paths; the three removed selection controls are not reintroduced in asset settings. This change does not delete or rewrite historical artifacts or reprocess published messages.

### Updating an existing playbook consumer

Update the producer and consumer together before activating the new import on an environment. An existing playbook that requires the old Ready or Request artifacts cannot consume the new combined layout unchanged.

- Remove the sequential `filter_1` readiness and `filter_2` Request-presence/correlation gates; connect Start to the existing first business-flow block.
- Map both analyzers directly to the single email artifact's original-mail `vaultId`.
- Map Release/Deny identity to the event, not optional display fields or artifact iteration. Do not multiply actions based on optional metadata.
- Map prompt sender/recipient and original-mail link from the email artifact, and subject/identity from the event as shown above.
- Read event ID/status/owner, analysis results, prompt answers and action outcomes from their existing native sources. Do not add lookup actions, a replacement readiness flag, or a helper playbook.
- Preserve the analysis matrix, scores 20/80, existing retry behavior, Yes/No prompt, Send-Mail and success-dependent completion.

Playbooks are maintained separately from this app/runbook repository. Use native VPE mappings and generation; a local app test does not validate a customer's editable graph or execute its nine decision branches. The coordinated consumer update and native save/reload remain a separate deployment acceptance step. Do not deploy the changed producer while its active consumer still depends on removed artifacts.

## Enterprise Security setup

Before enabling ES intake, register these additional fields in the target ES environment:

- `quarantine_identity`
- `work_item_id`
- `source_data_identifier`
- `quarantine`
- `eml_sha256`

The app does not register them automatically. Configure the native ES target and security domain. Urgency and investigation type are optional. **on es poll** requires an ES target; **on poll** respects the asset's native target selection.

The external SOAR URL must be a valid HTTPS address reachable by analysts. ES original-mail and attachment links use that URL, not an internal loopback endpoint. Verify downloads and permissions from the analyst interface.

ES receives the email headers/body, original-email link, attachment links and registered correlation fields. Header values are limited to 8,192 characters; body text to 256,000 characters. The outer plain-text body is preferred, then HTML; attachment content and attached-message descendants are excluded. A 2 MiB metadata check runs before attachment-link entries are added. The original Vault EML remains the complete source.

Configured drilldown searches require `name`, `search`, `earliest` and `latest`. Dashboard drilldowns require `app`, `dashboard_id` and `name`; token entries require a name and string value.

## Reading poll results

A poll reaching its summary step returns these fields, including on a partial failure:

| Fields | Meaning |
|---|---|
| `candidates`, `candidate_window`, `results_may_be_truncated` | Discovery count/window and whether the first-page window was full |
| `containers_created`, `messages_published` | Successful publications in this poll; both counters have the same meaning |
| `active_messages`, `active_limit` | Current unresolved identities and configured ceiling |
| `requested_containers`, `terminal_observed` | Admission limit for this poll and confirmed terminal observations |
| `errors` | Error count, not an array |
| `ingestion_enabled`, `ingest_target` | `true` for executed intake and target `soar` or `es` |

Inspect the action status and message as well as its counts. Target-resolution failures, an invalid ES target or a lock failure can return an error before any summary exists. Missing counters are not measured zeroes. Prepared containers from a failed import are not necessarily counted as successful publications.

## Publication failures

| Observation | Behavior |
|---|---|
| Retryable preparation failure | Preparation can resume on a later poll |
| Deterministic MIME/size defect | Item stays `blocked` until eligible operator recovery |
| Explicit SOAR final-artifact rejection | Item returns to `ready` for a later retry |
| Definitive ES HTTP 4xx, except 408/425/429/499 | Item returns to `ready` |
| ES receipt confirms zero created, one failed, no findings and the expected or empty container list | Item returns to `ready` |
| Timeout, HTTP 408/425/429/499 or 5xx, malformed/mismatched receipt, unknown acceptance | Item stays `publishing`; no automatic resubmission |

A failed action alone is not proof that the remote system rejected the submission. Microsoft status reconciliation continues, including for an uncertain publication.

## Operator recovery

Use **recover quarantine ingestion** with an exact `identity`, a `resolution` and an `operator_note` of 1–1,000 characters.

- **`retry_preparation`:** Correct the cause first. Allowed from `blocked`, `reserved`, `preparing` or `ready`. With a bound container it resumes at `preparing`; otherwise at `reserved`. A subsequent poll performs the work. It cannot reset `publishing` or `published`.
- **`confirm_published`:** Allowed only from `publishing`. Independently verify the exact final email artifact (Ready artifact in separate layout) or ES finding, linked container and automation evidence, then record your evidence in the note. This is an operator assertion: the app records `published` without verifying that evidence itself or sending another submission.

Neither option frees a Microsoft-status-controlled slot, releases/denies mail or dispatches analysis by itself. Do not clear state or create a replacement asset to hide uncertain publication.

For uncertain Release/Deny operations, use **reconcile quarantine operation**, not ingestion recovery. See the [runbook troubleshooting guide](troubleshooting.md).

## Limits

- EML: 24 MiB; MIME: 200 parts, depth 30, 100 attachments and 48 MiB combined decoded attachment data.
- Ingestion state: 1,000 records. Active records are never evicted; capacity errors prevent new admissions while existing work continues.
- Terminal retention: 1–365 days, default 30. After expiry, a reappearing source identity may be admitted again.
- Poll work budget: 600 seconds between calls. An in-flight operation may exceed that budget; remaining work continues on later polls. Individual Azure job timeout settings are separate.

These limits apply independently of the analyzer's queue capacity. Intake does not serialize analysis across separate containers.
