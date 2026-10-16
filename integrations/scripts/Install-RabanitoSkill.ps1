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
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$relativeSkill = switch ($Client) {
    'Claude' { '.claude\skills\rabanito-second-brain' }
    'Codex'  { '.agents\skills\rabanito-second-brain' }
    'Hermes' { 'skills\rabanito-second-brain' }
}
$sourceSkill = Join-Path $repoRoot $relativeSkill
$sourceFile = Join-Path $sourceSkill 'SKILL.md'

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

function Get-TreeShape([string]$Directory) {
    $files = @(Get-ChildItem -LiteralPath $Directory -Force -File -Recurse | ForEach-Object {
        $_.FullName.Substring($Directory.Length).TrimStart('\', '/')
    } | Sort-Object)
    $directories = @(Get-ChildItem -LiteralPath $Directory -Force -Directory -Recurse)
    return @{ Files = $files; Directories = $directories }
}

if (-not (Test-Path -LiteralPath $sourceFile -PathType Leaf)) {
    throw "Falta el paquete de Skill fuente: $sourceFile"
}
$null = Assert-NoReparseComponents $sourceSkill
$null = Assert-NoReparseComponents $sourceFile
$resolvedRoot = Assert-NoReparseComponents $SkillRoot
if (-not (Test-Path -LiteralPath $resolvedRoot -PathType Container)) {
    throw 'SkillRoot debe ser una carpeta existente; el instalador no crea ni adivina la raíz del cliente.'
}

$destination = Join-Path $resolvedRoot $skillName
$sourceHash = (Get-FileHash -LiteralPath $sourceFile -Algorithm SHA256).Hash.ToLowerInvariant()
if (Test-Path -LiteralPath $destination) {
    $null = Assert-NoReparseComponents $destination
    if (-not (Test-Path -LiteralPath $destination -PathType Container)) {
        throw "El destino existe y no es una carpeta: $destination"
    }
    $manifestPath = Join-Path $destination $manifestName
    $installedSkill = Join-Path $destination 'SKILL.md'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $installedSkill -PathType Leaf)) {
        throw "El destino ya existe y no pertenece a este instalador; no se sobrescribió: $destination"
    }
    $shape = Get-TreeShape $destination
    if ($shape.Directories.Count -ne 0 -or
        ($shape.Files -join '|') -ne (('SKILL.md', $manifestName | Sort-Object) -join '|')) {
        throw "La instalación contiene archivos adicionales; no se modificó: $destination"
    }
    try { $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw "El manifiesto de instalación no es válido; no se modificó: $destination" }
    $installedHash = (Get-FileHash -LiteralPath $installedSkill -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($manifest.client -ne $Client -or $manifest.skill_name -ne $skillName -or
        $manifest.content_sha256 -ne $installedHash) {
        throw "El destino cambió desde la instalación; no se sobrescribió ni eliminó: $destination"
    }
    if ($installedHash -eq $sourceHash) {
        Write-Output "Already installed and unchanged: $destination"
        return
    }
    throw "Hay una versión anterior intacta. Desinstálala con Uninstall-RabanitoSkill.ps1 y luego reinstala; no se sobrescribió: $destination"
}

if (-not $PSCmdlet.ShouldProcess($destination, "Install $Client skill '$skillName'")) { return }

$temporaryName = '.rabanito-install-' + [Guid]::NewGuid().ToString('N')
$temporary = Join-Path $resolvedRoot $temporaryName
try {
    $null = New-Item -ItemType Directory -Path $temporary
    Copy-Item -LiteralPath $sourceFile -Destination (Join-Path $temporary 'SKILL.md')
    $manifest = @{
        schema_version = 1
        client = $Client
        skill_name = $skillName
        content_sha256 = $sourceHash
    } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText(
        (Join-Path $temporary $manifestName), $manifest,
        [Text.UTF8Encoding]::new($false)
    )
    [IO.Directory]::Move($temporary, $destination)
    Write-Output "Installed $Client skill: $destination"
}
finally {
    if (Test-Path -LiteralPath $temporary -PathType Container) {
        $resolvedTemporary = [IO.Path]::GetFullPath($temporary)
        $expectedParent = [IO.Path]::GetFullPath($resolvedRoot).TrimEnd('\')
        if ((Split-Path -Parent $resolvedTemporary).TrimEnd('\') -ne $expectedParent -or
            (Split-Path -Leaf $resolvedTemporary) -notmatch '^\.rabanito-install-[0-9a-f]{32}$') {
            throw 'El temporal de instalación no coincide con el nombre esperado; se dejó intacto.'
        }
        Remove-Item -LiteralPath $resolvedTemporary -Recurse -Force
    }
}
