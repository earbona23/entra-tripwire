# How this gets installed, and whether it should ship an `.exe`

This page answers a question that was asked directly: *is a standalone `.exe` viable, or
something easy and interactive for the user?* It is written as an engineering assessment
rather than a recommendation looking for evidence, so every load-bearing claim below has a
source or a measurement, and the places where the evidence ran out are marked as such.

Measured and sourced on 2026-10-24 against `main`.

---

## The verdict in five lines

1. An `.exe` is **technically trivial and strategically wrong**, but not for the reason
   usually given. The usual reason is "code signing is expensive". The real reason is that
   **signing does not remove the warning**: Microsoft states that a newly signed binary
   "could still show a SmartScreen warning until its hash or publisher certificate
   accumulates sufficient evidence of positive reputation", typically "several weeks and
   hundreds of clean installs from a wide audience".
2. **EV no longer buys the way out.** Microsoft's own wording: "EV certificates no longer
   bypass SmartScreen... Paying a premium for EV solely to avoid SmartScreen warnings is no
   longer justified." The historical instant-trust behaviour is gone.
3. That is a trap specific to a tool at this stage of adoption: reputation is earned by
   volume, so a low-volume security tool would pay for a certificate **every year** and
   still hand an Entra administrator a red warning dialog — while competing against tools
   that produce no dialog at all.
4. **WinGet is not an escape hatch, and this is a hard no, not a judgement call.** The
   manifest schema has no installer type for a PowerShell module, and the community repo
   states "**Scripts are expressly disallowed as installers**".
5. **`Install-Module` is already the native idiom of this niche.** Nine comparable
   Entra/M365 tools were checked and **none ships an `.exe`**. The lever worth pulling is
   not the file format: it is a guided first-run **inside** PowerShell, where the user
   already is.

**Recommendation: keep PowerShell Gallery as the only distribution channel. Do not build
an `.exe`. Spend the effort on a guided setup command and on manifest quality.**

---

## 1. How this niche installs and runs software today

### The evidence from comparable tools

Distribution channel of every Entra/M365 administration or assessment tool checked, read
from each project's own installation documentation:

| Tool | PowerShell Gallery | `.exe` | Source |
|---|:--:|:--:|---|
| Microsoft Graph PowerShell SDK | yes — "the preferred installation method" | no | [Learn](https://learn.microsoft.com/powershell/microsoftgraph/installation) |
| ExchangeOnlineManagement | yes | no | [Learn](https://learn.microsoft.com/powershell/exchange/exchange-online-powershell-v2) |
| MicrosoftTeams | yes | no | [Learn](https://learn.microsoft.com/microsoftteams/teams-powershell-install) |
| AzureADAssessment (Microsoft) | yes | no | [GitHub](https://github.com/AzureAD/AzureADAssessment) |
| Maester | yes | no | [GitHub](https://github.com/maester365/maester) |
| ScubaGear (CISA) | yes — "the recommended way to install it is from PSGallery" | no (a `.zip` is also offered) | [GitHub](https://github.com/cisagov/ScubaGear) |
| Monkey365 | yes | no (GitHub release `.zip` also offered) | [GitHub](https://github.com/silverhack/monkey365) |
| MSOnline / AzureAD | was a Gallery module; deprecated 2024-03-30 | no | [Learn](https://learn.microsoft.com/powershell/azure/active-directory/overview) |
| 365Inspect | no — distributed as a `.ps1` from a clone | no | [GitHub](https://github.com/soteria-security/365Inspect) |

**Nine tools, zero `.exe` files.** Eight install with `Install-Module`; the ninth is a
script. An Entra administrator evaluating this module is a person who already has a
PowerShell window open, has already run `Install-Module Microsoft.Graph.Authentication`,
and for whom `Install-Module EntraTripwire` is the *lower*-friction path — it is the one
they do not have to think about.

This is observational evidence about distribution channels. It is not survey data on
administrator preference, and no such survey was found.

### What `Install-Module` actually costs the user

- **No elevation.** For PowerShellGet 2.0.0+ on PowerShell 6+, "the default is
  CurrentUser, which doesn't require elevation for install"
  ([Learn](https://learn.microsoft.com/powershell/module/powershellget/install-module)).
- **No PATH or discovery work.** The CurrentUser module directory is already on the
  default `PSModulePath`
  ([about_PSModulePath](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_psmodulepath)),
  so command autoloading works with no further step.
- **`Install-Module` is in the box.** "If you are running PowerShell 6.0 or later, you
  already have a newer version of PowerShellGet and PackageManagement installed"
  ([Learn](https://learn.microsoft.com/powershell/gallery/powershellget/install-powershellget)).
  This module requires PowerShell 7.2, so there is no bootstrap step at all.
- **One prompt, and it is real.** PSGallery is **not** trusted by default
  ([Learn](https://learn.microsoft.com/powershell/gallery/powershellget/supported-repositories)).
  A first-time user sees:

  ```
  Untrusted repository
  You are installing the modules from an untrusted repository. If you trust this
  repository, change its InstallationPolicy value by running the Set-PSRepository cmdlet.
  Are you sure you want to install the modules from 'PSGallery'?
  [Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"):
  ```

  **The default answer is `N`.** This is the single real friction point in the current
  install, and it is one keystroke. It is also the same prompt every tool in the table
  above produces, so it costs nothing *relative* to the alternatives.

### What Windows does to an unsigned `.exe`

Microsoft publishes a behaviour table for a first download
([SmartScreen reputation](https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation)):

| What you ship | What the user sees on first download |
|---|---|
| Microsoft Store | no warning |
| Signed, OV or EV | "app flagged as unrecognized until reputation accumulates; verified publisher name is displayed" |
| **Unsigned** | **"Windows protected your PC". "User must choose 'Run anyway' before the app can run. Enterprise policy can prevent continuation entirely."** |
| Self-signed | same as unsigned |

Three further facts make the unsigned case worse than it looks:

- **Reputation is per-hash *and* per-certificate.** "A negative or unknown reputation for a
  file's hash or its publisher's certificate can cause warnings to show." Without a
  signature, "reputation must build for each new version of your files, starting with zero
  reputation. Reputation cannot transfer from previous versions unless both were signed
  using the same publisher identity." **Every release would start from zero.**
- **Smart App Control on Windows 11 is stricter.** It "may supersede SmartScreen
  Application Reputation" and "will block execution of unsigned files unless the file has a
  positive reputation", and it applies "to all executable files, not just those downloaded
  from the Internet".
- **There is no appeal for the common case.** "There is no need (or mechanism) to manually
  submit a file for SmartScreen reputation review for consumer endpoints."

### Application Control — and an honest correction

It is tempting to say "an `.exe` is blocked by App Control but a module merely degrades".
That is too generous to the module, and the difference was measured rather than assumed.

Under an App Control policy, untrusted PowerShell runs in `ConstrainedLanguage` mode (CLM),
which "limits the object types that can be used"
([about_Language_Modes](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_language_modes)).
Checking this module's source against the documented allow-list:

| Construct | Uses in `src/` | Permitted in CLM? |
|---|:--:|---|
| `[Math]::` | 24 | **no** — not on the allow-list |
| `[Environment]::` | 3 | **no** |
| `[Convert]::`, `[StringComparer]::`, `[DateTimeKind]::`, `[DateTimeOffset]::` | 4 | **no** |
| `[System.Net.WebUtility]::` (report escaping) | 1 | **no** |
| `[System.Security.Cryptography.RandomNumberGenerator]::` (decoy password) | 1 | **no** |
| `[System.Globalization.DateTimeStyles]::` | 1 | **no** |
| `[string]`, `[datetime]`, `[guid]`, `[timespan]`, `[pscustomobject]`, `[hashtable]` | many | yes |

**33 uses of types outside the allow-list**, 24 of them `[Math]::` inside the scoring
engine itself. On top of that, `EntraTripwire.psm1` loads the module by dot-sourcing every
`.ps1` under `Private/` and `Public/`, and dot-sourcing is restricted under CLM.

So the honest statement is: **under an enforced App Control policy, neither format works
unless the policy explicitly allows it.** The `.exe` is blocked outright; the module is not
blocked but breaks. Application Control is therefore **not** a reason to prefer one format
over the other. It is a reason to know that locked-down tenants need a policy rule either
way — and in such a tenant, signing the `.ps1`/`.psm1` files would let a publisher rule
trust them, which is a cheaper and more targeted fix than shipping a different file type.

This is not a claim that the module has been tested under CLM. It has not. The table is a
static count against Microsoft's published allow-list, and the practical failure mode
should be confirmed on a locked-down host before anything is promised to such a tenant.

### What a code signing certificate actually demands

If an `.exe` were shipped anyway, these are the real costs. Note that the hardware
requirement now applies to **OV as well as EV** — the "cheap OV certificate you download as
a `.pfx`" no longer exists.

- **Hardware key storage is mandatory.** The CA/Browser Forum *Baseline Requirements for
  the Issuance and Management of Publicly-Trusted Code Signing Certificates*
  ([v3.11.0](https://cabforum.org/working-groups/code-signing/requirements/)) lists, in its
  Relevant Dates table, effective **2023-06-01**: "CAs SHALL ensure that the Subscriber's
  Private Key is generated, stored, and used in a suitable Hardware Crypto Module", applied
  to Non-EV certificates as well. Compliance means a hardware token, an HSM, or a
  CA-hosted cloud signing service.
- **Certificates expire faster than they used to.** Same document, effective
  **2026-03-01**: "For Code Signing Certificates issued on or after March 1st, 2026, the
  validity period MUST NOT exceed 460 days." This is an annual renewal and an annual
  re-validation, not a one-time cost.
- **Price.** Microsoft's own two pages disagree with each other — one gives OV at
  "$150–300/year" and EV at "$400+/year"
  ([code-signing-options](https://learn.microsoft.com/windows/apps/package-and-deploy/code-signing-options)),
  another gives OV at "$300–500/year"
  ([signing-package-overview](https://learn.microsoft.com/windows/msix/package/signing-package-overview#signing-options)).
  Reseller listings put Sectigo OV around $219–399/yr and DigiCert EV around $620–685/yr.
  **Treat all of these as indicative:** the figures could not be confirmed from the
  certificate authorities' own pages, and DigiCert's store page returned monthly and total
  prices that do not reconcile.
- **Azure Artifact Signing — Microsoft's managed service — is probably not available
  here.** It is the cheapest credible option at "~$9.99/month"
  ([Learn](https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation))
  with FIPS 140-3 Level 3 HSMs and no token to carry
  ([overview](https://learn.microsoft.com/azure/artifact-signing/overview)). But the
  eligibility rules bite twice:
  - **Individuals must be in the US or Canada.** The
    [quickstart](https://learn.microsoft.com/azure/artifact-signing/quickstart) states
    "Individual developers must be located in the United States or Canada." The maintainer
    is in the Dominican Republic, so the individual path is closed.
  - **The organisation path may fail on age.** `signing-package-overview` states
    "Organizations must have a verifiable tax history of three or more years", and a
    Microsoft staff answer in 2025 declined an onboarding because the organisation "was
    incorporated less than three years ago"
    ([Q&A](https://learn.microsoft.com/answers/a/12302018)). The current quickstart no
    longer contains that sentence, so **today's enforcement is genuinely unresolved** — but
    ArrankaGo LLC was formed in April 2026, so a refusal is plausible. Billing starts when
    the account is created and is "not calculated on a pro rata basis"
    ([FAQ](https://learn.microsoft.com/azure/artifact-signing/faq#cost-management-and-billing)),
    so finding out costs money.
  - And it would not solve the problem anyway: "Azure Artifact Signing does **not** provide
    instant SmartScreen trust... your apps will initially show a SmartScreen warning until
    your publisher identity builds sufficient download reputation"
    ([Learn](https://learn.microsoft.com/windows/msix/package/sign-msix-package-guide)).

**The conclusion that matters:** every signing option costs real money annually, the
cheapest one is probably not available to this maintainer, and **none of them removes the
warning dialog for a tool without download volume.** An `.exe` would buy an annual bill and
a worse first impression than the `Install-Module` line the README already shows.

---

## 2. WinGet: can a PowerShell module be published there?

**No.** This was checked against the schema and the repository policy rather than inferred.

**The manifest schema has no module or script installer type.** From
[`manifest.installer.latest.json`](https://github.com/microsoft/winget-cli/blob/master/schemas/JSON/manifests/latest/manifest.installer.latest.json),
the `InstallerType` enum is exactly:

```
msix, msi, appx, exe, zip, inno, nullsoft, wix, burn, pwa, portable, font
```

Nothing corresponds to a PowerShell module or a PowerShell Gallery package.

**The community repository bans scripts outright.**
[`Policies.md`](https://github.com/microsoft/winget-pkgs/blob/master/doc/Policies.md):
"**Scripts are expressly disallowed as installers.** Examples include: Batch files
(`.bat`), PowerShell scripts (`.ps1`)". The supported types are listed as "MSIX, APPX, MSI,
Exe-based installers, Font files".

**Could a `.zip` with `NestedInstallerType: portable` smuggle a module folder in?**
Mechanically perhaps, but it would not produce a working install. The `portable` flow
downloads files, writes uninstall registry entries, and adds the location to **`PATH`**
([FAQ](https://github.com/microsoft/winget-pkgs/blob/master/doc/FAQ.md)). PowerShell
discovers modules through **`PSModulePath`**, not `PATH`, and nothing in the portable flow
touches `PSModulePath`. The user would end up having to run `Import-Module` against a full
filesystem path — strictly worse than `Install-Module`, and with `Update-Module` no longer
working. No precedent for a PowerShell module in `winget-pkgs` was found.

**What submission would require even if the format fit**, for the record: ten sequential
automated validation steps plus moderator approval; a multi-file manifest (the singleton
form "is prohibited in the community repository"); unattended installation ("must install
without requiring user interaction"); HTTPS URLs that are publicly accessible, stable and
version-specific, hosted on the publisher's own official domain rather than a mirror or
shortener; and a clean pass through static analysis and "multiple antivirus engines" —
"regardless of the application's legitimacy or intent". Notably, **no signing requirement
is documented** in the winget-pkgs validation docs, but the pipeline does check installer
URLs against SmartScreen reputation, which returns the problem from section 1.

**So WinGet is only reachable by first building and signing an installer.** It is a
consequence of the `.exe` decision, never an alternative to it.

---

## 3. The real options for "easy and interactive"

Four honest options, with what each one costs and what the product loses.

### Option A — A guided setup command inside PowerShell *(recommended)*

An interactive command that walks a first-time operator through connect → baseline → plant
→ watch → report, explaining each consent prompt before it appears and refusing to continue
when a prerequisite is missing.

- **Cost:** development time only. No certificate, no annual bill, no new artefact, no new
  release channel.
- **Why it fits:** it puts the guidance where the friction actually is. The hard part of
  this tool is not obtaining it — `Install-Module EntraTripwire` is one line. The hard part
  is the five decisions *after* install: which consent mode to use, how long to baseline,
  what to name a decoy, where to seed a secret, and what the bands mean. An `.exe` solves
  none of those. A wizard solves all of them.
- **What it loses:** nothing in distribution terms. It does add a surface that must be
  tested, and an interactive command is harder to test than a pure function.
- It also pairs with the strongest asset this module already has: `-Demo`. A prospective
  user can reach a scored result with no tenant and no credentials, which is a better
  evaluation experience than any installer can offer.

### Option B — The HTML report as the deliverable *(already shipped; lean on it harder)*

`Export-TripwireReport` writes a self-contained HTML file. For the audience who will never
open PowerShell — the manager, the client, the auditor — **this is the product**, and it
already requires nothing to view.

- **Cost:** none; it exists.
- **What it loses:** nothing. This is the part of the product most worth putting in front
  of someone, and `docs/images/sample-report.html` already lets a stranger see the output
  before installing anything.

### Option C — A packaged executable

Bundle the module with a PowerShell host into a single binary.

- **Cost:** a signing certificate annually (section 1), a second build and release pipeline,
  a second artefact to test, and a bigger download. And after all of it, a SmartScreen
  warning anyway until reputation accrues, which volume at this stage will not deliver.
- **What it loses, and this is the part that is easy to miss:**
  `Update-Module` stops being the update path, so updates become a manual re-download;
  the module stops being composable, so it cannot be called from a scheduled task,
  a container, or someone else's script; and it stops looking like the eight peer tools in
  the table above, which is a credibility cost in a niche where `Install-Module` *is* the
  signal of a normal tool.
- **When it would become right:** if the buyer were a non-technical analyst who never opens
  a shell, or if a GUI became the product. Neither is true today.

### Option D — Change nothing

- **Cost:** none.
- **What it loses:** the first-run experience stays a documentation problem. The README is
  good, but a new user still has to read it to get the sequence right, and some will not.

**Recommendation: A + B.** Keep the Gallery as the only channel, make the first run guided,
and treat the HTML report as the thing you show people. Revisit C only if a non-shell
audience becomes the buyer.

---

## 4. What the payment protects — and what it does not

This is the point most easily got wrong, so it is stated flatly:

> **The file format protects nothing. An `.exe` is not a licence enforcement mechanism.**

**What actually makes a customer pay** is that the three paid capabilities — containment
execution, SOAR/SIEM delivery, and multiple tenant profiles — **are not present in the
public package at all.** They are in a separate module, `EntraTripwirePro`, and holding it
is the entitlement. A fork has to *write* those capabilities, which is a different kind of
work from removing a check.

**What does not protect it:**

- **Not the file format.** A compiled binary is not a licence boundary. PowerShell shipped
  inside an executable is still recoverable, and even if it were not, obfuscation is not
  entitlement. Packaging has never been the thing standing between a user and a paid
  feature here.
- **Not a licence check in MIT-licensed code.** This is the mistake the project already
  made and already corrected. A check inside MIT code is a line anyone may delete, the
  licence expressly permits deleting it, and underneath it sat working capability. That is
  why the code moved, and the reasoning is in [LICENSING.md](../LICENSING.md).
- **Not obscurity about what the module does.** Deliberately so: every verdict, the whole
  scoring engine, the containment plan and the Graph write allowlist stay public and
  readable, because a customer who cannot audit the detection has no reason to trust it.

**What the public package is therefore free to be:** maximally open and maximally easy to
install. There is no commercial reason to make the free module harder to obtain, inspect or
run — the boundary is drawn around capability, not around packaging. Any argument of the
form "an `.exe` would protect the revenue" is reasoning about the wrong boundary.

Two limits worth stating honestly, both already in `LICENSING.md`: every version already
published under MIT stays MIT for that version, so the boundary applies going forward only;
and nothing here prevents a competent engineer from writing their own containment — it only
means they have to write it.

---

## 5. What is missing for the install to be impeccable

Measured against `main`, in priority order.

### 5.1 The publishing workflow does not exist

`.github/workflows/ci.yml` is the only workflow, and it runs tests, lint and mutation — it
does **not** publish. A search of the repository for `Publish-Module`, `Publish-PSResource`
or an API-key secret returns nothing. **Publishing is therefore a manual
`Publish-Module` from a workstation**, which means:

- the published artefact is whatever was in that working directory, not a tagged commit;
- there is no record of which commit a Gallery version came from;
- the version on the Gallery and `ModuleVersion` in the manifest can drift silently;
- the one person who can publish is the one person who has the API key.

This is the largest gap, and it is a bus-factor problem as much as a quality one. A
tag-triggered publish job — gated on the existing green CI, reading the API key from a
repository secret, and refusing to publish if `ModuleVersion` does not match the tag — would
make releases reproducible and auditable. It needs a new secret, so it is a decision rather
than a change to make unilaterally.

### 5.2 Manifest metadata gaps that cost discoverability

The Gallery renders specific manifest fields on the package page
([Learn](https://learn.microsoft.com/powershell/gallery/concepts/package-manifest-affecting-ui)).
Measured against `src/EntraTripwire/EntraTripwire.psd1`:

| Field | State on `main` | Effect |
|---|---|---|
| `IconUri` | **absent** | No icon on the package page or in search results. Every established tool in this niche has one. |
| `ReleaseNotes` | a **link** to `CHANGELOG.md` | The Gallery renders this field as the release notes *text*. A reader sees a URL where they expected to see what changed. |
| `Tags` | 12 tags, including `PSEdition_Core` | Good, but missing the documented **platform** tags. "By tagging your package with the compatible platform(s) it will be included in the Gallery search filters" — `Windows`, `Linux`, `MacOS`. |
| `Description` | present, 3 sentences | Strong, and it leads with the problem rather than the architecture. |
| `ProjectUri` / `LicenseUri` | present | Correct. |
| `HelpInfoURI` | absent | Only needed for `Update-Help`; the module has no updatable help, so leaving it out is correct. |
| `CompatiblePSEditions` | absent | For 5.1+ this manifest key, not the `PSEdition_*` tag, is the real declaration. Worth adding — but it is a behavioural key, not metadata, so it is flagged here rather than changed. |

Icon requirements, for when one is made: "The URI should point to an 85x85 image with
transparency background. The URI **must** be a direct link to the image file and **must
not** go to a web page or a file in the PowerShell Gallery package."

### 5.3 `RequiredModules` — the current choice is right, and should stay

The manifest deliberately declares no `RequiredModules`, with a comment explaining why:
a hard dependency would turn "try it against the fixtures" into an install.

This is the correct call and it is worth defending explicitly, because it looks like an
omission. `Microsoft.Graph.Authentication` is loaded lazily by `Connect-EntraTripwire` and
is only needed to reach a real tenant. CI proves the promise holds by running the whole
DEMO path with the Graph SDK filtered out of `PSModulePath`. Adding `RequiredModules` would
cost a multi-megabyte dependency install before a prospective user could see a single
scored trip, and would buy nothing — the dependency is genuinely optional.

The one gap is a *documentation* gap rather than a manifest one: the Gallery page shows a
"Dependencies" section, and a reader who checks it sees nothing and cannot tell whether that
means "no dependencies" or "undeclared dependencies". The `Description` should say that
Graph is needed only for a live tenant. **This is fixed in the `Description` as part of this
change.**

### 5.4 The update flow is manual, and nothing says so

`Update-Module` "installs a module's newest version" and, with no parameters, "updates all
installed modules"
([Learn](https://learn.microsoft.com/powershell/module/powershellget/update-module)).
There is **no notification mechanism** — no documented way for the Gallery to tell an
installed user that a new version exists. A user must poll.

For a detection tool this matters more than for most software: an operator running a stale
version may be missing a fix to a signal, and will not be told. No documentation currently
mentions `Update-Module` at all. The cheap fix is one line in the README's install block;
the thorough fix, for later, is for the module to note the installed-versus-available
version when a guided setup command runs.

### 5.5 Smaller items

- **PSGallery's untrusted-repository prompt is undocumented.** The README shows
  `Install-Module EntraTripwire -Scope CurrentUser` without mentioning that the default
  answer to the resulting prompt is `N`. A user who presses Enter gets nothing installed and
  no obvious reason why. One sentence fixes it.
- **No Authenticode signature on the module files.** The Gallery does not require one
  ("The minimum requirements to publish" do not include signing), and `Install-Module`
  verifies a catalog signature only when one exists. Signing is listed as a best practice.
  It is cheap to defer, but it is the one thing that would let a locked-down tenant trust
  the module by publisher rule rather than by hash — see the CLM discussion in section 1 —
  and it runs into the same certificate problem, so it is a cost question, not an oversight.
- **Version `1.0.0` with unreleased changes accumulated.** `CHANGELOG.md` has a populated
  `[Unreleased]` section including behavioural fixes. Until that ships as a version, a
  Gallery user installing `1.0.0` gets none of it.

---

## Sources

Microsoft Learn, read 2026-10-24:
[SmartScreen reputation](https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation) ·
[code signing options](https://learn.microsoft.com/windows/apps/package-and-deploy/code-signing-options) ·
[signing package overview](https://learn.microsoft.com/windows/msix/package/signing-package-overview) ·
[sign MSIX package guide](https://learn.microsoft.com/windows/msix/package/sign-msix-package-guide) ·
[Azure Artifact Signing overview](https://learn.microsoft.com/azure/artifact-signing/overview) ·
[Artifact Signing quickstart](https://learn.microsoft.com/azure/artifact-signing/quickstart) ·
[Artifact Signing FAQ](https://learn.microsoft.com/azure/artifact-signing/faq) ·
[App Control for Business](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/appcontrol) ·
[how App Control works with PowerShell](https://learn.microsoft.com/powershell/scripting/security/app-control/how-app-control-works) ·
[about_Language_Modes](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_language_modes) ·
[about_PSModulePath](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_psmodulepath) ·
[Install-Module](https://learn.microsoft.com/powershell/module/powershellget/install-module) ·
[Update-Module](https://learn.microsoft.com/powershell/module/powershellget/update-module) ·
[supported repositories](https://learn.microsoft.com/powershell/gallery/powershellget/supported-repositories) ·
[installing PowerShellGet](https://learn.microsoft.com/powershell/gallery/powershellget/install-powershellget) ·
[manifest fields affecting the Gallery UI](https://learn.microsoft.com/powershell/gallery/concepts/package-manifest-affecting-ui) ·
[Gallery publishing guidelines](https://learn.microsoft.com/powershell/gallery/concepts/publishing-guidelines) ·
[module PSEdition support](https://learn.microsoft.com/powershell/gallery/concepts/module-psedition-support) ·
[publishing a package](https://learn.microsoft.com/powershell/gallery/how-to/publishing-packages/publishing-a-package)

WinGet: [installer manifest schema](https://github.com/microsoft/winget-cli/blob/master/schemas/JSON/manifests/latest/manifest.installer.latest.json) ·
[Policies.md](https://github.com/microsoft/winget-pkgs/blob/master/doc/Policies.md) ·
[Validation.md](https://github.com/microsoft/winget-pkgs/blob/master/doc/Validation.md) ·
[FAQ.md](https://github.com/microsoft/winget-pkgs/blob/master/doc/FAQ.md) ·
[Authoring.md](https://github.com/microsoft/winget-pkgs/blob/master/doc/Authoring.md)

CA/Browser Forum:
[Baseline Requirements for Code Signing, v3.11.0](https://cabforum.org/working-groups/code-signing/requirements/)

Certificate prices are indicative reseller figures and are **not** confirmed from CA
pricing pages; see the caveat in section 1.
