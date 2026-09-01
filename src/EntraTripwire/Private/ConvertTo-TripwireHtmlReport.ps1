<#
.SYNOPSIS
    Render scored trips into a single self-contained HTML file.

.DESCRIPTION
    No external CSS, no fonts, no scripts from a CDN: an incident report has to open on an
    isolated workstation. Everything is escaped before it reaches the document, because
    every string in a trip -- display names, user agents, operations -- is attacker-
    influenced by construction. A deception tool that renders attacker-chosen text into a
    responder's browser has handed the attacker the responder.

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

    $rows = foreach ($t in $ordered) {
        $withheld = if (@($t.Withheld).Count -gt 0) { 'withheld: ' + (@($t.Withheld) -join ', ') } else { 'all signals evaluated' }
        $signalHtml = foreach ($s in $t.Signals) {
            $state = if ($s.Available) { "$([Math]::Round($s.Raw * 100))%" } else { 'n/a' }
            "<li><b>$(ConvertTo-TripwireHtmlEncoded $s.Name)</b> <span class=""w"">x$($s.Weight)</span> <span class=""r"">$state</span><br><span class=""why"">$(ConvertTo-TripwireHtmlEncoded $s.Rationale)</span></li>"
        }
        @"
<tr class="band-$(ConvertTo-TripwireHtmlEncoded $t.Band.ToLowerInvariant())">
  <td class="score"><span class="pill">$([int]$t.Confidence)</span><br><span class="band">$(ConvertTo-TripwireHtmlEncoded $t.Band)</span></td>
  <td>
    <div class="hdr">$(ConvertTo-TripwireHtmlEncoded $t.DecoyName) <span class="mono">$(ConvertTo-TripwireHtmlEncoded $t.Touch.operation)</span></div>
    <div class="meta">$(ConvertTo-TripwireHtmlEncoded $t.Touch.timestamp.ToString('u')) &middot; actor $(ConvertTo-TripwireHtmlEncoded $t.ActorLabel) &middot; $(ConvertTo-TripwireHtmlEncoded $t.Touch.ip) $(ConvertTo-TripwireHtmlEncoded $t.Touch.country) &middot; $(ConvertTo-TripwireHtmlEncoded $t.Touch.source)</div>
    <div class="cov">$(ConvertTo-TripwireHtmlEncoded $withheld)</div>
    $(if ($t.SuppressionReason) { "<div class=""sup"">Suppressed: $(ConvertTo-TripwireHtmlEncoded $t.SuppressionReason)</div>" })
    <ul class="signals">$($signalHtml -join '')</ul>
  </td>
</tr>
"@
    }

    $demoBanner = if ($Demo) {
        '<div class="demo">DEMO MODE &mdash; every trip below was scored from the synthetic fixtures shipped with the module. No tenant was contacted.</div>'
    }
    else { '' }

    $degradedBanner = if ($degraded -gt 0) {
        "<div class=""warn"">$degraded trip(s) were scored with at least one signal withheld. Their confidence is a FLOOR, not a measurement &mdash; a withheld signal contributes zero and can only push a score down.</div>"
    }
    else { '' }

    @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EntraTripwire report</title>
<style>
:root{color-scheme:light dark;--bg:#0f1115;--fg:#e6e8ee;--mut:#9aa3b2;--card:#171a21;--line:#252a34;
--hi:#ff5d5d;--md:#ffb020;--lo:#4a9eff;--sp:#6b7280}
@media (prefers-color-scheme:light){:root{--bg:#f7f8fa;--fg:#12151b;--mut:#5b6472;--card:#fff;--line:#e3e6ec}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:28px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);margin-bottom:18px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}
.c{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:110px}
.c .n{font-size:22px;font-weight:600}.c .l{color:var(--mut);font-size:12px}
.demo{background:#1d3a5f;color:#cfe4ff;border-radius:8px;padding:10px 14px;margin-bottom:14px}
.warn{background:#4a3410;color:#ffd9a0;border-radius:8px;padding:10px 14px;margin-bottom:14px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
td{padding:12px 14px;border-top:1px solid var(--line);vertical-align:top}
tr:first-child td{border-top:none}
.score{width:96px;text-align:center}
.pill{display:inline-block;min-width:44px;padding:4px 8px;border-radius:999px;font-weight:700;color:#0b0d11;background:var(--sp)}
.band-high .pill{background:var(--hi)}.band-medium .pill{background:var(--md)}.band-low .pill{background:var(--lo)}
.band{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}
.hdr{font-weight:600}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--mut);font-size:12px}
.meta,.cov{color:var(--mut);font-size:12px}.cov{font-style:italic}
.sup{color:var(--mut);font-size:12px;margin-top:4px}
ul.signals{list-style:none;margin:8px 0 0;padding:0;display:grid;gap:4px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}
ul.signals li{border-left:2px solid var(--line);padding-left:8px;font-size:12px}
.w,.r{color:var(--mut);font-size:11px}.why{color:var(--mut)}
footer{color:var(--mut);font-size:12px;margin-top:18px}
</style></head><body>
<h1>EntraTripwire &mdash; decoy activity</h1>
<div class="sub">$(ConvertTo-TripwireHtmlEncoded $TenantLabel) &middot; generated $([DateTime]::UtcNow.ToString('u'))</div>
$demoBanner
$degradedBanner
<div class="cards">
  <div class="c"><div class="n">$high</div><div class="l">High confidence</div></div>
  <div class="c"><div class="n">$medium</div><div class="l">Medium</div></div>
  <div class="c"><div class="n">$low</div><div class="l">Low</div></div>
  <div class="c"><div class="n">$suppressed</div><div class="l">Suppressed</div></div>
  <div class="c"><div class="n">$degraded</div><div class="l">Scored degraded</div></div>
</div>
<table>$($rows -join '')</table>
<footer>Confidence is a weighted score, not a probability. A withheld signal contributes zero, so a
degraded score is a lower bound. Containment is never eligible below the High band.</footer>
</body></html>
"@
}
