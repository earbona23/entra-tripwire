# Licensing

Short version: everything in this repository is MIT. The paid edition is not a different
codebase, it is an entitlement checked by code that is in this repository and that you can
read. This page says exactly what that means, including the parts that are uncomfortable,
because a licence page that only states the convenient half is not worth reading.

## What the MIT Licence gives you

The full text is in `LICENSE`. In practice it means you may use this module commercially,
modify it, embed it in your own product, redistribute it, and keep your modifications
private, for free, with no obligation to contribute anything back.

The single condition is the one in the licence: the copyright notice and the permission
notice must be included in all copies or substantial portions of the software. See
`NOTICE`.

## What the MIT Licence does not give you

- **It gives you no rights in the name.** "entra-tripwire" and the project's identity are
  not licensed to you by `LICENSE`. See `TRADEMARKS.md`.
- **It gives you no right to imply endorsement.** You may say your fork is based on
  entra-tripwire. You may not present it in a way that suggests it is published,
  maintained, reviewed or approved by the maintainer.
- **It gives you no warranty and no support.** That is the part in capital letters.

## The Pro edition

Pro is an entitlement, not a separate download. `Enable-TripwirePro` verifies an ECDSA
P-256 token offline against a public key embedded in the module, and three features read
that entitlement: containment **execution**, SOAR/SIEM delivery, and multiple tenant
profiles. Everything that detects and scores is free and is identical in both.

The verification code is in `src/EntraTripwire/Private/License.ps1` and it is MIT, like the
rest of the repository. So let us be direct about the consequence: **the MIT Licence
permits you to fork this module and delete the entitlement check.** Nothing in `LICENSE`
forbids it, and this page is not going to pretend otherwise.

What that fork does not come with is a licence key, the private signing key, updates, the
test suite being run against your changes by anyone but you, or any answer when the write
allowlist behaves in a way you did not expect against a production tenant. The paid edition
exists to fund maintenance of the free one. If the module is useful to your organisation,
the honest options are to buy a licence or to
[sponsor](https://github.com/sponsors/earbona23) it.

The signing key is private and lives outside this repository. Only the verification public
key ships inside the module: it can verify a signature and can never mint one. A forged key
is therefore not a thing that exists, and removing the check entirely is the only path --
which is a licensing question, not a security one. A bypass that *also* causes a tenant
write is a different matter and is in scope for `SECURITY.md`.

## Future licence changes

The maintainer reserves the right to license future versions of this project under
different terms. That is a normal reservation for a maintained project and it is stated
here so that nobody is surprised by it later.

What such a change could never do, and what you can rely on: **every version already
published under the MIT Licence stays MIT for that version, permanently.** A licence change
binds new releases only. Code you already obtained under MIT remains yours to use, modify
and redistribute under MIT, and the published git history stays as it is.

## Contributions

Contributions are accepted under the Developer Certificate of Origin and the Contributor
Licence Agreement. See `CONTRIBUTING.md`, `DCO` and `CLA.md`. Contributors keep the
copyright in their own work.

## Questions

Licensing and purchasing questions: **earbona@arrankago.com**. Security reports do not go
to that address; see `SECURITY.md`.
