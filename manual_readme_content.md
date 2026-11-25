## Set up Microsoft Defender quarantine intake

Deploy the matching Azure Automation runbook before installing the SOAR app.
Use the Automation Account managed identity for Exchange and a separate,
read-only Entra app registration for job output. Configure one ingesting asset
per tenant. Import does not release email.

See the [project documentation](https://github.com/reisball/ms-quarantine-for-splunk-soar#documentation)
for permissions, installation, native SOAR and optional Enterprise Security
intake, and operational troubleshooting. This is a community-maintained app.
