# Permissions, and why each one

Consent is derived from what you asked for. `Connect-EntraTripwire -Mode Detect` requests
two read scopes and nothing else — an operator who only wants detection is never asked to
consent to a write.

## By mode

| Scope | Detect | Plant | Contain | Why |
|---|:--:|:--:|:--:|---|
| `AuditLog.Read.All` | yes | yes | yes | Read sign-in logs and directory audit logs. This is how a touch is observed at all. |
| `Directory.Read.All` | yes | yes | yes | Resolve actors and targets to directory objects, and build the tenant baseline. |
| `User.ReadWrite.All` | — | yes | yes | Create and delete decoy users; disable an identity and revoke its sessions during containment. |
| `Application.ReadWrite.OwnedBy` | — | yes | yes | Create and delete decoy application registrations. `OwnedBy` rather than the tenant-wide variant: the module only ever needs to manage the applications it created. |

## The write surface is enumerated, not promised

`Private/Invoke-TripwireGraphWrite.ps1` holds an allowlist of eight operations. Anything not
on it throws before a request is issued:

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1.0/users` | Plant a decoy user |
| POST | `/v1.0/applications` | Plant a decoy application |
| POST | `/v1.0/applications/{id}/addPassword` | Plant a decoy client secret |
| POST | `/v1.0/users/{id}/revokeSignInSessions` | Containment: revoke the actor's refresh tokens |
| PATCH | `/v1.0/users/{id}` | Containment: disable an identity — **body must be exactly `{"accountEnabled": false}`** |
| PATCH | `/v1.0/servicePrincipals/{id}` | Containment: disable a decoy service principal — same body constraint |
| DELETE | `/v1.0/users/{id}` | Remove a decoy user |
| DELETE | `/v1.0/applications/{id}` | Remove a decoy application |

Two consequences worth stating plainly:

- **The gateway can disable an identity and is structurally incapable of enabling one.** The
  only permitted PATCH body is `accountEnabled: false`. A bug, a bad merge or a hostile input
  cannot turn containment into a privilege grant.
- **No allowlist entry grants anything.** No role assignment, no app role assignment, no
  consent grant, no group membership, no authentication method, no key. `tests/Safety.Tests.ps1`
  asserts each of those is refused by name.

Reads have their own gateway, `Invoke-TripwireGraphRequest`, which has no `-Method` parameter
and no `-Body` parameter and hardcodes `GET` at its single call site. A test asserts that
`Invoke-MgGraphRequest` appears in exactly those two files in the whole module.

## Application registration

Delegated permissions work for interactive use. For a scheduled watcher, register an
application with **application** permissions for the scopes above and grant admin consent.

Two things to get right, because they defeat the tool if you get them wrong:

1. **Do not name the watcher application anything that reveals what it does.** An intruder
   who enumerates applications and finds `Tripwire Decoy Monitor` has been handed the list of
   objects to avoid.
2. **Do not grant the watcher more than the mode you actually run.** A scheduled *detector*
   needs the two read scopes. If containment runs from an operator's session instead, the
   scheduled identity never needs a write scope at all — and an identity that cannot write is
   an identity that cannot be turned against the tenant.

## What the module never asks for

`Mail.Read`, `Files.Read.All`, `Policy.ReadWrite.*`, `RoleManagement.*`, `AppRoleAssignment.*`,
`Directory.ReadWrite.All`. If a future change needs any of them, the write allowlist and the
tests are where that argument has to be won first.
