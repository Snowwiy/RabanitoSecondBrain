[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Claude', 'Codex', 'Hermes')]
    [string]$Client,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SkillRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$skillName = 'rabanito-second-brain'
$manifestName = '.rabanito-install.json'

function Assert-NoReparseComponents([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Se rechazó una ruta con symlink/reparse point: $current"
        }
        $parent = Split-Path -Parent $current
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
    }
    return [IO.Path]::GetFullPath($Path)
}

$resolvedRoot = Assert-NoReparseComponents $SkillRoot
if (-not (Test-Path -LiteralPath $resolvedRoot -PathType Container)) {
    throw 'SkillRoot debe ser una carpeta existente; no se crearon ni adivinaron rutas.'
}
$destination = Join-Path $resolvedRoot $skillName
if (-not (Test-Path -LiteralPath $destination)) {
    Write-Output "Not installed: $destination"
    return
}
$null = Assert-NoReparseComponents $destination
if (-not (Test-Path -LiteralPath $destination -PathType Container)) {
    throw "El destino no es una carpeta; no se eliminó: $destination"
}

$manifestPath = Join-Path $destination $manifestName
$skillPath = Join-Path $destination 'SKILL.md'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $skillPath -PathType Leaf)) {
    throw "Falta el manifiesto de propiedad o el SKILL.md; no se eliminó nada: $destination"
}
$files = @(Get-ChildItem -LiteralPath $destination -Force -File -Recurse | ForEach-Object {
    $_.FullName.Substring($destination.Length).TrimStart('\', '/')
} | Sort-Object)
$directories = @(Get-ChildItem -LiteralPath $destination -Force -Directory -Recurse)
if ($directories.Count -ne 0 -or
    ($files -join '|') -ne (('SKILL.md', $manifestName | Sort-Object) -join '|')) {
    throw "La carpeta incluye archivos ajenos; no se eliminó nada: $destination"
}
try { $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json }
catch { throw "El manifiesto no es válido; no se eliminó nada: $destination" }
$installedHash = (Get-FileHash -LiteralPath $skillPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($manifest.schema_version -ne 1 -or $manifest.client -ne $Client -or
    $manifest.skill_name -ne $skillName -or $manifest.content_sha256 -ne $installedHash) {
    throw "La instalación cambió o no coincide con este cliente; no se eliminó nada: $destination"
}

if ($PSCmdlet.ShouldProcess($destination, "Remove unchanged managed $Client skill '$skillName'")) {
    Remove-Item -LiteralPath $destination -Recurse -Force
    Write-Output "Uninstalled $Client skill: $destination"
}
