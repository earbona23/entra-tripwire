<#
.SYNOPSIS
    Render scored trips into a single self-contained HTML file.

.DESCRIPTION
    No external CSS, no fonts, no scripts from a CDN: an incident report has to open on an
    isolated workstation. Everything is escaped before it reaches the document, because
    every string in a trip -- display names, user agents, operations -- is attacker-
    influenced by construction. A deception tool that renders attacker-chosen text into a
    responder's browser has handed the attacker the responder.

    Two things beyond escaping make this document safe to pass around:

      * A Content-Security-Policy of default-src 'none'. The report is a flat file with no
        scripts and nothing to fetch, so the policy costs nothing and means a browser will
        refuse to load anything from it even if a future change, or a smuggled string,
        tried. A security report that can phone home is not a security report.
      * It is readable by somebody who has never used this tool. The verdict, what each
        band means, and what to do next are IN the document, not in the README, because an
        incident report gets forwarded and the README does not go with it.

    The header states coverage BEFORE findings: how many trips were withheld signals, and
    how many were suppressed. A low trip count on a degraded run is not good news, and this
    report refuses to let it look like good news.
#>
function ConvertTo-TripwireHtmlEncoded {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Value)

    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

<#
.SYNOPSIS
    A confidence as the engine computed it, not as an integer cast rounds it.
.DESCRIPTION
    The score is a weighted sum carried to one decimal. [int] on 99.6 is 100, and a report
    that prints 100 for a score of 99.6 is overstating evidence in an incident document.
#>
function Format-TripwireConfidence {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Value)

    if ($null -eq $Value) { return '--' }
    return ('{0:0.#}' -f [double]$Value)
}

function ConvertTo-TripwireHtmlReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Trip,
        [string] $TenantLabel = 'unspecified tenant',
        [switch] $Demo
    )

    $ordered = @($Trip | Sort-Object -Property Confidence -Descending)
    $high = @($ordered | Where-Object { $_.Band -eq 'High' }).Count
    $medium = @($ordered | Where-Object { $_.Band -eq 'Medium' }).Count
    $low = @($ordered | Where-Object { $_.Band -eq 'Low' }).Count
    $suppressed = @($ordered | Where-Object { $_.Band -eq 'Suppressed' }).Count
    $degraded = @($ordered | Where-Object { $_.Degraded }).Count

    # The verdict and the next steps come from the same function the console uses, so the
    # report and the terminal can never disagree about what this run means.
    $summary = $ordered | Get-TripwireSummary -Demo:$Demo

    # The observed window, derived from the trips rather than from a parameter. A report
    # that states a window it was not given would be stating something it does not know.
    $stamps = @($ordered | ForEach-Object { $_.Touch.timestamp } | Where-Object { $null -ne $_ } | Sort-Object)
    $window = if ($stamps.Count -gt 0) {
        "touches from $($stamps[0].ToString('u')) to $($stamps[-1].ToString('u'))"
    }
    else { 'no touch in this set carried a resolvable timestamp' }

    $stepHtml = foreach ($s in $summary.NextSteps) {
        $cmd = if ($s.Command) { "<div class=""cmd""><code>$(ConvertTo-TripwireHtmlEncoded $s.Command)</code></div>" } else { '' }
        "<li>$(ConvertTo-TripwireHtmlEncoded $s.Action)$cmd</li>"
    }

    $rows = foreach ($t in $ordered) {
        $withheld = if (@($t.Withheld).Count -gt 0) { 'withheld: ' + (@($t.Withheld) -join ', ') } else { 'all signals evaluated' }
        # A touch can reach the report with no resolvable timestamp -- Graph omits
        # properties rather than nulling them, and such a touch is scored with the signals
        # that need a clock withheld rather than being dropped. Calling .ToString() on it
        # throws, and the whole report with it, so the absence is rendered as an absence.
        $when = if ($null -ne $t.Touch.timestamp) { $t.Touch.timestamp.ToString('u') } else { 'no timestamp in the source record' }
        # Built from the parts that are actually present. A directory audit record carries
        # no address and no country, and joining the fields unconditionally printed the
        # separator twice with nothing between them -- which reads as data this tool lost
        # rather than data the log never had.
        $meta = @(
            (ConvertTo-TripwireHtmlEncoded $when)
            "actor $(ConvertTo-TripwireHtmlEncoded $t.ActorLabel)"
            $(if (-not [string]::IsNullOrWhiteSpace([string]$t.Touch.ip)) { ConvertTo-TripwireHtmlEncoded $t.Touch.ip })
            $(if (-not [string]::IsNullOrWhiteSpace([string]$t.Touch.country)) { ConvertTo-TripwireHtmlEncoded $t.Touch.country })
            (ConvertTo-TripwireHtmlEncoded $t.Touch.source)
            "$(ConvertTo-TripwireHtmlEncoded $t.DistinctDecoys) distinct decoy(s) by this actor in the window"
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        $signalHtml = foreach ($s in $t.Signals) {
            if ($s.Available) {
                $pct = [int][Math]::Round([double]$s.Raw * 100)
                if ($pct -lt 0) { $pct = 0 }
                if ($pct -gt 100) { $pct = 100 }
                $state = "$pct%"
                $bar = "<span class=""bar""><i style=""width:$pct%""></i></span>"
            }
            else {
                $state = 'withheld'
                $bar = '<span class="bar na"></span>'
            }
            "<li><span class=""sn""><b>$(ConvertTo-TripwireHtmlEncoded $s.Name)</b> <span class=""w"">weight $($s.Weight)</span> <span class=""r"">$state</span></span>$bar<span class=""why"">$(ConvertTo-TripwireHtmlEncoded $s.Rationale)</span></li>"
        }
        @"
<tr class="band-$(ConvertTo-TripwireHtmlEncoded $t.Band.ToLowerInvariant())">
  <td class="score"><span class="pill">$(Format-TripwireConfidence $t.Confidence)</span><br><span class="band">$(ConvertTo-TripwireHtmlEncoded $t.Band)</span></td>
  <td>
    <div class="hdr">$(ConvertTo-TripwireHtmlEncoded $t.DecoyName) <span class="mono">$(ConvertTo-TripwireHtmlEncoded $t.Touch.operation)</span></div>
    <div class="meta">$($meta -join ' &middot; ')</div>
    <div class="cov">$(ConvertTo-TripwireHtmlEncoded $withheld)</div>
    $(if ($t.SuppressionReason) { "<div class=""sup"">Suppressed: $(ConvertTo-TripwireHtmlEncoded $t.SuppressionReason)</div>" })
    <ul class="signals">$($signalHtml -join '')</ul>
  </td>
</tr>
"@
    }

    $demoBanner = if ($Demo) {
        '<div class="demo"><b>DEMO MODE</b> &mdash; every trip below was scored from the synthetic fixtures shipped with the module. No tenant was contacted.</div>'
    }
    else { '' }

    $degradedBanner = if ($degraded -gt 0) {
        "<div class=""warn""><b>Coverage</b> &mdash; $degraded trip(s) were scored with at least one signal withheld. Their confidence is a FLOOR, not a measurement &mdash; a withheld signal contributes zero and can only push a score down.</div>"
    }
    else { '' }

    $empty = if ($ordered.Count -eq 0) {
        '<p class="none">No decoy was touched in this set. That is good news only if decoys are planted and the window covered them.</p>'
    }
    else { '' }

    @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<title>EntraTripwire report &mdash; $(ConvertTo-TripwireHtmlEncoded $TenantLabel)</title>
<style>
:root{color-scheme:light dark;
--bg:#0f1115;--fg:#e8eaf0;--mut:#9aa3b2;--card:#171a21;--card2:#1c2029;--line:#262b35;
--hi:#ff5f5f;--md:#f5a623;--lo:#5aa2ff;--sp:#7a8494;--acc:#8ab4ff}
@media (prefers-color-scheme:light){:root{--bg:#f6f7f9;--fg:#11141a;--mut:#555f6e;--card:#fff;--card2:#f1f3f7;--line:#dfe3ea;--acc:#1b5fd0}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 24px 56px}
.brand{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--acc);font-weight:700}
h1{font-size:26px;line-height:1.2;margin:6px 0 6px;letter-spacing:-.01em}
h2{font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:var(--mut);
margin:30px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.sub{color:var(--mut);margin:0 0 20px}
.demo,.warn{border-radius:8px;padding:11px 14px;margin-bottom:12px;font-size:13px;border:1px solid transparent}
.demo{background:#15304e;color:#d5e6ff;border-color:#27507d}
.warn{background:#412c0c;color:#ffdca6;border-color:#6d4a14}
@media (prefers-color-scheme:light){.demo{background:#e8f1ff;color:#14365f;border-color:#b9d4f7}
.warn{background:#fff5e0;color:#5d4211;border-color:#f0d9a4}}
.verdict{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--sp);
border-radius:10px;padding:16px 18px;margin-bottom:16px}
.verdict.v-high{border-left-color:var(--hi)}.verdict.v-medium{border-left-color:var(--md)}
.verdict.v-low{border-left-color:var(--lo)}
.vlabel{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--mut);margin-bottom:6px;font-weight:700}
.verdict p{margin:0;font-size:16px;line-height:1.45}
.verdict ol{margin:14px 0 0;padding-left:22px}
.verdict li{margin:0 0 10px;color:var(--fg)}
.cmd{margin-top:5px}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;
background:var(--card2);border:1px solid var(--line);border-radius:5px;padding:2px 6px;
display:inline-block;max-width:100%;overflow-wrap:anywhere;color:var(--fg)}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:6px}
.c{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:116px;flex:1 1 116px}
.c .n{font-size:24px;font-weight:650;line-height:1.1}.c .l{color:var(--mut);font-size:12px;margin-top:2px}
.legend{display:grid;gap:8px;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));margin:0 0 4px;padding:0;list-style:none}
.legend li{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:12px;color:var(--mut)}
.legend b{display:block;color:var(--fg);font-size:13px;margin-bottom:2px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th{text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);
padding:10px 14px;background:var(--card2);border-bottom:1px solid var(--line)}
td{padding:13px 14px;border-top:1px solid var(--line);vertical-align:top}
tbody tr:first-child td{border-top:none}
.score{width:104px;text-align:center}
.pill{display:inline-block;min-width:48px;padding:4px 9px;border-radius:999px;font-weight:700;color:#0b0d11;background:var(--sp)}
.band-high .pill{background:var(--hi)}.band-medium .pill{background:var(--md)}.band-low .pill{background:var(--lo)}
.band{display:inline-block;margin-top:4px;font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}
.hdr{font-weight:650;font-size:15px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--mut);font-size:12px;font-weight:400}
.meta,.cov{color:var(--mut);font-size:12px}.cov{font-style:italic;margin-top:2px}
.sup{color:var(--fg);background:var(--card2);border:1px solid var(--line);border-radius:6px;
padding:6px 9px;font-size:12px;margin-top:7px}
ul.signals{list-style:none;margin:10px 0 0;padding:0;display:grid;gap:9px;grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}
ul.signals li{border-left:2px solid var(--line);padding-left:9px;font-size:12px}
.sn{display:block}.w,.r{color:var(--mut);font-size:11px}
.bar{display:block;height:4px;border-radius:2px;background:var(--line);margin:4px 0 3px;overflow:hidden}
.bar i{display:block;height:100%;background:var(--acc)}.bar.na{background:repeating-linear-gradient(90deg,var(--line) 0 4px,transparent 4px 8px)}
.why{color:var(--mut);display:block}
.none{color:var(--mut)}
.method{color:var(--mut);font-size:12.5px}
.method p{margin:0 0 8px}
footer{color:var(--mut);font-size:11.5px;margin-top:26px;padding-top:12px;border-top:1px solid var(--line)}
@media print{
:root{--bg:#fff;--fg:#000;--mut:#333;--card:#fff;--card2:#f4f4f4;--line:#bbb;--acc:#333}
body{background:#fff;color:#000;font-size:10.5pt}
.wrap{max-width:none;padding:0}
h2{margin-top:18px}
.demo,.warn,.verdict,.c,.legend li,table,.sup{border-color:#999}
tr,li,.verdict{page-break-inside:avoid}
h2{page-break-after:avoid}
footer{page-break-before:avoid}
}
</style></head><body><div class="wrap">
<header>
<div class="brand">EntraTripwire</div>
<h1>Decoy activity report</h1>
<p class="sub">$(ConvertTo-TripwireHtmlEncoded $TenantLabel) &middot; $(ConvertTo-TripwireHtmlEncoded $window) &middot; generated $([DateTime]::UtcNow.ToString('u'))</p>
</header>
$demoBanner
$degradedBanner
<div class="verdict v-$(if ($high -gt 0) { 'high' } elseif ($medium -gt 0) { 'medium' } elseif ($low -gt 0) { 'low' } else { 'none' })">
<div class="vlabel">Verdict</div>
<p>$(ConvertTo-TripwireHtmlEncoded $summary.Verdict)</p>
<ol>$($stepHtml -join '')</ol>
</div>
<h2>Counts</h2>
<div class="cards">
  <div class="c"><div class="n">$high</div><div class="l">High confidence</div></div>
  <div class="c"><div class="n">$medium</div><div class="l">Medium</div></div>
  <div class="c"><div class="n">$low</div><div class="l">Low</div></div>
  <div class="c"><div class="n">$suppressed</div><div class="l">Suppressed</div></div>
  <div class="c"><div class="n">$degraded</div><div class="l">Scored degraded</div></div>
</div>
<h2>What the bands mean</h2>
<ul class="legend">
  <li><b>High</b> The only band containment is eligible in, and only when the score was not degraded.</li>
  <li><b>Medium</b> Evidence worth a human look. No automatic action is ever taken here.</li>
  <li><b>Low</b> A decoy was touched, but not in a pattern this engine calls an intrusion.</li>
  <li><b>Suppressed</b> A known-benign cause matched. Shown with its reason, never hidden.</li>
</ul>
<h2>Findings</h2>
$empty
<table>
<thead><tr><th scope="col">Confidence</th><th scope="col">Touch, actor and the signals behind the score</th></tr></thead>
<tbody>$($rows -join '')</tbody>
</table>
<h2>How to read this</h2>
<div class="method">
<p>Each decoy is an identity, application or credential that no legitimate process has any
reason to touch. A touch is scored from four weighted signals &mdash; the purity of the decoy,
how unusual the origin is for this tenant, how many distinct decoys the same actor walked
inside the correlation window, and the hour &mdash; which sum to a confidence out of 100.</p>
<p>Confidence is a weighted score, not a probability. A signal that could not be evaluated
contributes zero and the remaining weights are never renormalised upward, so a degraded
score is a lower bound on the evidence rather than a measurement of it.</p>
<p>Suppressed touches are listed with the rule that suppressed them. A suppression rule that
hides evidence is indistinguishable from a bug that loses it.</p>
</div>
<footer>EntraTripwire &middot; self-contained report: no scripts, no external styles, no fonts and
nothing to fetch. It opens correctly from a local disk on a machine with no network.</footer>
</div></body></html>
"@
}
