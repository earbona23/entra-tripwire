# Licensing

Short version: everything in this repository is MIT, and the paid capabilities are not in
this repository. They are a separate module. This page says exactly what that means,
including the parts that are uncomfortable, because a licence page that only states the
convenient half is not worth reading.

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

Pro is a separate module, `EntraTripwirePro`, published privately rather than here, and
holding it is the entitlement. Three capabilities live in it: containment **execution**,
SOAR/SIEM delivery, and multiple tenant profiles. Everything that detects and scores is
free, is in this repository, and is identical in both.

**This used to work the other way round, and the change is the honest part.** Until
October 2026 the paid capabilities were in this repository behind a licence check written
in MIT-licensed code. Let us be direct about what that meant: the MIT Licence permits you
to fork this module and delete a check, and deleting that one would have uncovered working
capability underneath. Nothing in `LICENSE` forbade it and this page did not pretend
otherwise.

Now there is nothing to uncover. The question this module asks is "is the paid module
installed?", and removing the question does not install it. A fork has to **write** those
three capabilities, which is a different thing from deleting a line.

Two consequences worth stating, because they cut both ways:

- **What is already published stays MIT, per version, for ever.** Every commit made before
  the split is on GitHub under MIT, with the old gate in it. A licence change or a code
  move only ever applies going forward. If you want that old version, the licence lets you
  have it.
- **What you can audit shrank, and deliberately not in the part that matters.** You can no
  longer read the code that performs a containment write. You can still read every verdict,
  the whole scoring engine, the containment plan, and the Graph write allowlist that the
  paid module is made to issue its writes through. That last one is the point: the paid
  module cannot make a call this repository does not permit.

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
