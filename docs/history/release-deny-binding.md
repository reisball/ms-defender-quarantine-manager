# Historical Release/Deny capability binding (retired since Runbook 3.4.1)

> **Historical only — not a current execution or CI gate.** App 3.7.4 pairs
> with Runbook 3.4.5 (bounded/redacted diagnostics patch). It does not run the synthetic binder probe or
> parameter-set gate described below. After the exact selected source status
> (`Requested` by default, `NotReleased` for explicit needs_review), it invokes
> the real cmdlet once and returns native binder/command-not-found errors.
> Deny of NotReleased remains tenant-unverified. See
> [RUNBOOK_DEBUG_GUIDE.md](../troubleshooting.md) for current behavior.
> Identify the current paired artifact using release-kit checksums and executable result fingerprints.

## Historical purpose (3.2.0–3.4.0)

The retired design required proof that the exact PowerShell arguments could
bind to the loaded `Release-QuarantineMessage` function without invoking it.

Runbook 3.2.0 introduced a fail-closed metadata heuristic. It required the
business arguments to be mandatory and excluded optional parameters belonging
to the other operation. That assumption was false for the generated
ExchangeOnlineManagement REST proxy and caused Runbook 3.2.0–3.3.1 to reject a
bindable release locally with `disposition_capability_unconfirmed`.

## Retired binding algorithm (Runbook 3.2.0-3.4.0)

The historical algorithm read command metadata, followed bounded alias hops,
rejected incompatible/missing mandatory arguments and custom `ValidateScript`,
then generated a metadata-only proxy with PowerShell `CommandMetadata` and
`ProxyCommand`. Its body returned `$PSCmdlet.ParameterSetName` without calling
the original command. A nonempty resolved set confirmed local binding only;
errors, ambiguity and unexpected output remained unconfirmed. This algorithm
was removed; do not restore it as an execution prerequisite.

## Historical captured EXO 3.5.0 regression shape

The redacted customer Inspect evidence contained these business parameter
sets:

```text
Identitities[Identity=optional,Identities=required,ActionType=optional] |
IdentityOnly[Identity=required,ActionType=optional] |
OceReleaseToAll[ActionType=optional,ReleaseToAll=required] |
OceReleaseToUser[ActionType=optional] |
OrgReleaseToAll[Identity=optional,Identities=optional,ActionType=optional,ReleaseToAll=required] |
OrgReleaseToUser[Identity=optional,Identities=optional,ActionType=optional]
```

No customer identifiers, message metadata, tenant IDs, tokens, or role names
were part of the fixture.

## Former regression matrix (3.2.0-3.4.0)

| Fixture | Release | Deny | Original command body |
|---|---|---|---|
| Captured overlapping EXO shape | `OrgReleaseToAll` | `Identitities` | Once, after precondition and binding checks pass |
| Truly incompatible split sets | Fail closed | Fail closed | Never |
| Valid binding while RBAC diagnostic cmdlets are unavailable | Confirm binding | Confirm binding | Once for the requested operation |
| Alias to supported concrete command | Confirm binding | Confirm binding | Never during probe |
| Supplied parameter with `ValidateScript` | Fail closed without executing script | Fail closed without executing script | Never |
| Standard exclusive unit fixture | `Release` | `Deny` | Once, after precondition and binding checks pass |

The former binder CI contract asserted the captured description and default
set. These historical fixtures are not a current matcher/change gate. Current
CI exercises real invocation shapes against mocks, not a synthetic prerequisite.

## Historical evidence boundary

A confirmed probe proved only local PowerShell argument resolution, not RBAC,
policy, eligibility, server-side app-only support or final quarantine state.
`cmdlet_capability_parameter_set` was a retired probe field, not current output.
Current results keep supplied argument metadata separate from native execution
and observed postconditions; see the current debug guide. Optional read-only
RBAC diagnostics are not an execution prerequisite. Offline fixtures and older
customer evidence do not establish positive App 3.7.4 native-chain acceptance.
