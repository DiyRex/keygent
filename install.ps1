# keygent installer for Windows (PowerShell 5.1+ or 7). No admin rights needed.
#
#   irm https://raw.githubusercontent.com/DiyRex/keygent/main/install.ps1 | iex
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/DiyRex/keygent/main/install.ps1))) -Version v0.1.0 -AddToPath
#
# What it does:
#   1. downloads the release zip, SHA256SUMS and SHA256SUMS.sigstore.json
#   2. verifies the Sigstore signature of SHA256SUMS (keyless, pinned to this repo's release workflow)
#      using your cosign.exe, or a pinned cosign it downloads to a temp dir and checks by SHA-256 first
#   3. verifies the zip's SHA-256 against the signed SHA256SUMS
#   4. refuses downgrades unless -AllowDowngrade, installs to %LOCALAPPDATA%\Programs\keygent\keygent.exe (stable path used by hooks)
#   5. adds that folder to your *user* PATH only if you agree (or pass -AddToPath)
#
# Env-var equivalents (for `irm | iex`): KEYGENT_VERSION, KEYGENT_ADD_TO_PATH=1, KEYGENT_ALLOW_DOWNGRADE=1
[CmdletBinding()]
param(
  [string]$Version = $env:KEYGENT_VERSION,
  [switch]$AddToPath = ($env:KEYGENT_ADD_TO_PATH -eq '1'),
  [switch]$AllowDowngrade = ($env:KEYGENT_ALLOW_DOWNGRADE -eq '1'),
  [switch]$InsecureSkipSignature
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo          = 'DiyRex/keygent'
$CosignVersion = 'v3.1.4'
$CosignAsset   = 'cosign-windows-amd64.exe'   # also used on ARM64 via built-in x64 emulation
$CosignSha256  = 'cbe953787074611f1334cbf37dc1cf953995bb8c45398eb4fc7bb781d29c1f2a'
$IdentityRe    = '^https://github\.com/DiyRex/keygent/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
$OidcIssuer    = 'https://token.actions.githubusercontent.com'
$Dest          = Join-Path $env:LOCALAPPDATA 'Programs\keygent'

function Say($m)  { Write-Host "keygent-install: $m" }
function Fail($m) { throw "keygent-install: error: $m" }

# ── platform → release target ────────────────────────────────────────────────
$arch = $env:PROCESSOR_ARCHITEW6432; if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
switch ($arch) {
  'AMD64' { $Target = 'x86_64-pc-windows-msvc' }
  'ARM64' { $Target = 'aarch64-pc-windows-msvc' }
  default { Fail "unsupported architecture $arch (supported: x64, ARM64)" }
}

# ── resolve version ──────────────────────────────────────────────────────────
if (-not $Version) {
  $req = [Net.WebRequest]::Create("https://github.com/$Repo/releases/latest")
  $req.AllowAutoRedirect = $false
  $resp = $req.GetResponse()
  $Version = ($resp.Headers['Location'] -split '/')[-1]
  $resp.Close()
}
if ($Version -notmatch '^v\d+\.\d+\.\d+$') { Fail "no release found (got '$Version')" }

# ── downgrade check ──────────────────────────────────────────────────────────
$Exe = Join-Path $Dest 'keygent.exe'
if (Test-Path $Exe) {
  $cur = (& $Exe version 2>$null | Select-String -Pattern 'v?\d+\.\d+\.\d+' | Select-Object -First 1).Matches.Value
  if ($cur) {
    if ([version]($Version.TrimStart('v')) -lt [version]($cur.TrimStart('v')) -and -not $AllowDowngrade) {
      Fail "installed $cur is newer than $Version — pass -AllowDowngrade to continue"
    }
  }
}

# ── download ─────────────────────────────────────────────────────────────────
$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("keygent-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
  $Name = "keygent-$Version-$Target"
  $Base = "https://github.com/$Repo/releases/download/$Version"
  Say "downloading keygent $Version for $Target"
  foreach ($f in @("$Name.zip", 'SHA256SUMS', 'SHA256SUMS.sigstore.json')) {
    Invoke-WebRequest -UseBasicParsing -Uri "$Base/$f" -OutFile (Join-Path $Tmp $f)
  }

  # ── signature ──────────────────────────────────────────────────────────────
  if ($InsecureSkipSignature) {
    Say 'WARNING: -InsecureSkipSignature — only the checksum is checked, the file''s origin is NOT verified'
  } else {
    $cosign = (Get-Command cosign.exe -ErrorAction SilentlyContinue).Source
    if (-not $cosign) {
      Say "cosign not found — fetching pinned cosign $CosignVersion into a temp dir"
      $cosign = Join-Path $Tmp 'cosign.exe'
      Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/sigstore/cosign/releases/download/$CosignVersion/$CosignAsset" -OutFile $cosign
      if ((Get-FileHash $cosign -Algorithm SHA256).Hash.ToLower() -ne $CosignSha256) { Fail 'cosign checksum mismatch — refusing to continue' }
    }
    Say "verifying signature (Sigstore, release workflow of $Repo)"
    & $cosign verify-blob (Join-Path $Tmp 'SHA256SUMS') `
        --bundle (Join-Path $Tmp 'SHA256SUMS.sigstore.json') `
        --certificate-identity-regexp $IdentityRe `
        --certificate-oidc-issuer $OidcIssuer `
        --certificate-github-workflow-repository $Repo *> $null
    if ($LASTEXITCODE -ne 0) { Fail 'signature verification FAILED — do not install this file' }
  }

  # ── checksum ───────────────────────────────────────────────────────────────
  $line = Get-Content (Join-Path $Tmp 'SHA256SUMS') | Where-Object { ($_ -split '\s+\*?')[1] -eq "$Name.zip" } | Select-Object -First 1
  if (-not $line) { Fail "$Name.zip is not listed in SHA256SUMS" }
  $expected = ($line -split '\s+')[0].ToLower()
  if ((Get-FileHash (Join-Path $Tmp "$Name.zip") -Algorithm SHA256).Hash.ToLower() -ne $expected) { Fail 'checksum mismatch — do not install this file' }
  Say 'signature and checksum OK'

  # ── install ────────────────────────────────────────────────────────────────
  Expand-Archive -Path (Join-Path $Tmp "$Name.zip") -DestinationPath $Tmp -Force
  $src = Join-Path $Tmp "$Name\keygent.exe"
  if (-not (Test-Path $src)) { Fail 'archive layout unexpected' }
  New-Item -ItemType Directory -Force -Path $Dest | Out-Null
  if (Test-Path $Exe) { Move-Item -Force $Exe "$Exe.old" }   # a running keygent.exe can be renamed but not overwritten
  Copy-Item $src $Exe -Force
  Remove-Item "$Exe.old" -Force -ErrorAction SilentlyContinue
  Say "installed $Exe ($Version)"

  # ── PATH (user scope, only with consent) ───────────────────────────────────
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (($userPath -split ';') -notcontains $Dest) {
    $add = $AddToPath
    if (-not $add -and [Environment]::UserInteractive) {
      $add = ((Read-Host "Add $Dest to your user PATH? [y/N]") -match '^(y|yes)$')
    }
    if ($add) {
      [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ";$Dest"), 'User')
      Say 'added to your user PATH (open a new terminal to use it)'
    } else {
      Say "not added to PATH — run it as `"$Exe`" or add $Dest yourself"
    }
  }
  Say 'next: keygent init   (if a broker is already running after an upgrade: keygent seal; keygent unseal)'
}
finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
