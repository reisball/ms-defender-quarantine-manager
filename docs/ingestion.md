# Email import

[Back to README](../README.md)

## How import works

The app imports only messages with Microsoft status `Requested`, meaning a recipient has requested release. There is no source-mode setting; obsolete settings from older versions are ignored. `NotReleased` mail is not imported.

Both targets export and validate the original EML. A MIME or size problem stops publication rather than importing incomplete mail.

### SOAR events

For each admitted message, the app:

1. exports and validates the original EML;
2. creates a container with automation disabled;
3. saves the original EML, attachments and selected metadata to the container and Vault;
4. publishes the completed SOAR event with automation enabled.

ES setup is not required for this path. See [Enterprise Security](#enterprise-security) for the separate findings path.

Use **one ingesting asset per tenant**. Each asset has its own state, so two assets can import the same message. Changing an asset's tenant, organization or target while it has tracked messages is rejected. Do not delete app state to get around this.

Schedule and container label are set in the asset's **Ingest Settings**. Disabling the schedule pauses automatic imports.

On upgrade, existing state is kept. Earlier `needs_review` scopes become Requested-only, published messages are not republished, and unfinished attempts are marked failed rather than replayed.

## Active-message limit

`on_poll_max_containers` (default 10, range 1–50) is the maximum number of messages whose Microsoft status is still unresolved. It is a total ceiling, not a per-poll increment.

- Imported, in-progress and failed messages all occupy a slot.
- A slot is freed after an exact read confirms `Released` or `Denied`, or when a successful exact lookup returns no result and the stored Microsoft expiry has passed. A missing result alone (even repeated), a failed lookup, or Exchange status `Error` does not prove retirement. Older records without a stored expiry still require a confirmed terminal status.
- An unresolved exact lookup or item-level `Error` is reported for that identity; other messages can still be imported if a slot is available. Unclassified, authentication and transport failures stop intake for that poll.
- Each poll first re-checks tracked statuses, then fills free slots from the first 50 `Requested` messages. There is no pagination or ordering guarantee, so an empty import does not prove the backlog is empty.
- Poll Now's `container_count` limits attempts in that poll and cannot exceed the asset limit.

## Playbook input (combined layout)

With `artifact_layout` = `combined`, each message produces **one event and one email artifact**. The artifact is saved last, with `run_automation=true`, after every Vault upload has finished. That save is what triggers playbooks. There are no Ready, Request or per-attachment artifacts.

| Playbook input | Data path |
|---|---|
| Original EML (for SAA, ANY.RUN and similar) | `artifact:*.cef.vaultId` |
| Sender / recipient (from Microsoft's quarantine list) | `artifact:*.cef.senderAddress` / `artifact:*.cef.recipientAddress` |
| Quarantine identity for Release/Deny | `container:data.quarantine_identity` |
| Subject | `container:name` |

`vaultId`, `senderAddress` and `recipientAddress` are always populated, whatever the field selections. The artifact is named after the subject (`No subject` if empty). Optional header fields are omitted when unavailable.

The Vault holds the original EML and all attachments, including inline parts and attached messages. Duplicate filenames get stable prefixes, and path components and control characters are removed. The original EML is always the authoritative copy.

The SOAR `separate` layout still uses Request, file, field and final Ready artifacts. The SOAR artifact layout does not apply to ES findings. Historical artifacts are not rewritten.

### Updating an existing playbook

A playbook built for the Ready/Request artifacts cannot consume the combined layout unchanged. Update it before activating the new app version:

- Remove the readiness (`filter_1`) and Request-presence (`filter_2`) gates and connect Start to the first business block.
- Map analyzers to the email artifact's `vaultId`.
- Map Release/Deny to `container:data.quarantine_identity`, not to optional fields or per-artifact iteration.
- Map prompt sender/recipient from the artifact and subject/identity from the event.

The app does not edit or activate playbooks. See the [SAA example](../examples/MS_Quarantine_SAA_Example/README.md) for a complete consumer.

## Enterprise Security

Use this section only when the asset targets **ES findings**. This path uploads the original EML and attachments to the SOAR Vault and submits a finding to ES after the uploads succeed. It does not use the SOAR event and email-artifact layout described above.

No custom ES field registration is needed. For Release/Deny, use `container:data.quarantine_identity` from the linked SOAR container.

- Configure the ES target and security domain. Urgency and investigation type are optional.
- **on es poll** requires an ES target. **on poll** uses the asset's target selection.
- Original-mail and attachment links use the external SOAR URL (`es_soar_base_url` or the platform URL). It must be HTTPS and reachable by analysts; check downloads from the analyst interface.
- ES receives headers (max 8,192 characters per original header value), body text (max 256,000 characters, plain text preferred over HTML), and attachment links. Attachment content is not sent.
- Drilldowns are optional. Searches need `name`, `search`, `earliest` and `latest`. Dashboard drilldowns need `app`, `dashboard_id` and `name`. Tokens need a name and a string value.

Native ES threat-analysis and automation settings control what happens next. ES accepting a finding does not mean analysis completed.

## Poll results

| Field | Meaning |
|---|---|
| `candidates`, `candidate_window`, `results_may_be_truncated` | Messages found, window size, and whether the window was full |
| `containers_created`, `messages_published` | Successful publications in this poll (same value) |
| `active_messages`, `active_limit` | Unresolved messages and the configured limit |
| `requested_containers`, `terminal_observed` | Attempt limit for this poll and confirmed `Released`/`Denied` observations |
| `errors` | Error count for this poll |
| `failed_imports` | Failed messages still holding a slot |
| `ingestion_enabled`, `ingest_target` | `true` when intake ran, and target `soar` or `es` |

Check the action status and message too. Some errors, such as an invalid target or lock failure, occur before any summary exists.

## Failed imports and Poll Now

Failed or interrupted imports are kept as failed and are never retried automatically. Scheduled polls skip them. To retry deliberately:

1. Read the action message and inspect any existing container, Vault files, email artifact or ES finding.
2. Fix the cause, for example invalid input or missing target permissions.
3. Run **Poll Now**. Failed messages that are still `Requested` within the first 50 candidates get a fresh attempt in their existing slot. New messages can also be admitted within the limit.
4. Verify the publication and downstream workflow.

Successful imports are never imported again while their record is retained. SOAR and ES calls are not a single transaction. In particular, if an ES response was lost, a retry can create a duplicate finding, so check ES first. Never clear app state or create a replacement asset to force a retry.

## Limits

| Limit | Value |
|---|---|
| Original EML | 24 MiB (transferred in chunks) |
| MIME structure | 200 parts, nesting depth 30 |
| Attachments | 100, with 48 MiB combined decoded size |
| Tracked messages | 1,000. Active records are never evicted; when full, new admissions fail. |
| Retention of resolved records | `worker_terminal_retention_days`, 1–365 days, default 30. After that, a reappearing message can be imported again. |
| Work budget | Scheduled poll: 600 s. Poll Now: 600 s for status checks plus 600 s for import. A running operation can exceed its budget, and unattempted messages wait for the next poll. |

Messages over a limit are rejected before publication rather than partially imported. The MIME parser bounds message structure, but it is not a malware filter.
