<#
.SYNOPSIS
  Batch driver for the vulnerability-detection pilot/full run. Uses ONLY
  Claude Code (headless `claude -p`) - no separate Anthropic API key.

.DESCRIPTION
  For each selected case, calls `claude -p "/run-case <case-file>"`, which
  internally invokes the vuln-generator and vuln-judge subagents and writes
  results/<run>/<case_id>.json. Idempotent: skips cases that already have a
  result file, so an interrupted run can simply be re-invoked. Retries a
  case once on failure.

.PARAMETER Run
  "pilot" (default) uses pilot/pilot_cases.json; "full_run" uses every case
  in cases/ with extraction_status "ok"; "ablation_baseline"/"ablation_context"
  use pilot/ablation_cases.json and invoke the matching ablation-arm command
  (see scripts/build_masked_context.py and the wider-context ablation notes
  in PROGRESS.md).

.EXAMPLE
  pwsh scripts/run_batch.ps1 -Run pilot
  pwsh scripts/run_batch.ps1 -Run ablation_context
#>
param(
    [ValidateSet("pilot", "full_run", "ablation_baseline", "ablation_context")]
    [string]$Run = "pilot"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$casesDir = Join-Path $root "cases"
$resultsDir = Join-Path $root "results\$Run"
$logsDir = Join-Path $resultsDir "logs"

New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null
New-Item -ItemType Directory -Force -Path $logsDir | Out-Null

$slashCommand = "/run-case"
if ($Run -eq "pilot") {
    $pilotPath = Join-Path $root "pilot\pilot_cases.json"
    $caseIds = (Get-Content $pilotPath -Raw | ConvertFrom-Json) | ForEach-Object { $_.case_id }
} elseif ($Run -eq "ablation_baseline" -or $Run -eq "ablation_context") {
    $ablationPath = Join-Path $root "pilot\ablation_cases.json"
    $caseIds = (Get-Content $ablationPath -Raw | ConvertFrom-Json) | ForEach-Object { $_.case_id }
    $slashCommand = "/run-case-$($Run -replace '_', '-')"
} else {
    $caseIds = Get-ChildItem $casesDir -Filter "*.json" | ForEach-Object {
        $data = Get-Content $_.FullName -Raw | ConvertFrom-Json
        if ($data.extraction_status -eq "ok") { $data.case_id }
    }
}

Write-Host "Run '$Run': $($caseIds.Count) case(s) selected"

$done = 0
$skippedExisting = 0
$failed = @()

foreach ($caseId in $caseIds) {
    $resultPath = Join-Path $resultsDir "$caseId.json"
    if (Test-Path $resultPath) {
        $skippedExisting++
        continue
    }

    $caseFile = "cases/$caseId.json"
    $logPath = Join-Path $logsDir "$caseId.log"
    $attempt = 0
    $success = $false

    while ($attempt -lt 2 -and -not $success) {
        $attempt++
        Write-Host "[$($done + $skippedExisting + 1)/$($caseIds.Count)] $caseId (attempt $attempt)..."
        try {
            & claude -p "$slashCommand $caseFile" *>> $logPath
            if (Test-Path $resultPath) {
                $success = $true
            } else {
                Write-Warning "$caseId : no result file after run (attempt $attempt)"
            }
        } catch {
            Add-Content -Path $logPath -Value "ERROR: $_"
            Write-Warning "$caseId : claude -p failed (attempt $attempt): $_"
        }
    }

    if ($success) {
        $done++
    } else {
        $failed += $caseId
    }
}

Write-Host ""
Write-Host "Done. Newly completed: $done, already had results: $skippedExisting, failed: $($failed.Count)"
if ($failed.Count -gt 0) {
    Write-Host "Failed case IDs (see logs/<case_id>.log):"
    $failed | ForEach-Object { Write-Host "  - $_" }
}
