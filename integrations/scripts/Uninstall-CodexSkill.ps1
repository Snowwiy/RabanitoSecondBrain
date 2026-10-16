[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param([Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SkillRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$engine = Join-Path $PSScriptRoot 'Uninstall-RabanitoSkill.ps1'
if (-not (Test-Path -LiteralPath $engine -PathType Leaf)) { throw "Falta el motor de desinstalación: $engine" }
$forward = @{ Client = 'Codex'; SkillRoot = $SkillRoot }
foreach ($name in @('WhatIf', 'Confirm')) {
    if ($PSBoundParameters.ContainsKey($name)) { $forward[$name] = $PSBoundParameters[$name] }
}
& $engine @forward
