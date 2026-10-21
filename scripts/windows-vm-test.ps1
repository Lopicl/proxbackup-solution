<#
.SYNOPSIS
  End-to-end test of proxbackup-agent on a real Windows machine (run elevated / as SYSTEM).

.DESCRIPTION
  Builds a test tree exercising Windows specifics (VSS on a locked file, attributes,
  creation times, Unicode, long paths, symlinks, junctions, alternate data streams, NTFS ACLs),
  backs it up to PBS with a VSS snapshot, restores it and compares everything. Then
  image-backs up a small VHDX volume and checks the restored image.
  Results are written as JSON to $Work\results.json.

.EXAMPLE
  .\windows-vm-test.ps1 -Agent C:\proxbackup\proxbackup-agent.exe -PbsHost 192.168.64.1:18007 `
     -Fingerprint aa:bb:... -AuthId 'admin@pbs!e2e' -Secret xxxx -Store ds1 -Ns proxbackup-win
#>
param(
  [Parameter(Mandatory)] [string]$Agent,
  [Parameter(Mandatory)] [string]$PbsHost,
  [Parameter(Mandatory)] [string]$Fingerprint,
  [Parameter(Mandatory)] [string]$AuthId,
  [Parameter(Mandatory)] [string]$Secret,
  [string]$Store = 'ds1',
  [string]$Ns = 'proxbackup-win',
  [string]$Id = 'win-vm',
  [string]$Work = 'C:\proxbackup-test',
  [switch]$SkipImage
)
$ErrorActionPreference = 'Stop'
$results = [ordered]@{ started = (Get-Date).ToString('o'); os = (Get-CimInstance Win32_OperatingSystem).Caption;
  arch = $env:PROCESSOR_ARCHITECTURE; checks = [ordered]@{}; errors = @() }
function Check($name, $ok, $detail = '') {
  $results.checks[$name] = [ordered]@{ ok = [bool]$ok; detail = "$detail" }
  Write-Host ("[{0}] {1} {2}" -f ($(if ($ok) { 'PASS' } else { 'FAIL' })), $name, $detail)
}
$env:PROXBACKUP_SECRET = $Secret
$common = @('-pbs', $PbsHost, '-fingerprint', $Fingerprint, '-auth-id', $AuthId, '-store', $Store, '-ns', $Ns, '-id', $Id)

function RunAgent([string[]]$agentArgs) {
  $out = & $Agent @agentArgs 2>&1 | Out-String
  $json = $null
  $i = $out.IndexOf("{`n"); if ($i -lt 0) { $i = $out.IndexOf("{`r`n") }
  if ($i -ge 0) { try { $json = $out.Substring($i) | ConvertFrom-Json } catch {} }
  return @{ text = $out; json = $json; code = $LASTEXITCODE }
}

try {
  # ---------- build test tree ----------
  if (Test-Path $Work) { cmd /c "rmdir /s /q `"$Work`"" | Out-Null }
  $src = Join-Path $Work 'data'
  New-Item -ItemType Directory -Force -Path $src, "$src\Documents\Über Ordner", "$src\empty dir" | Out-Null
  Set-Content -Path "$src\Documents\readme.txt" -Value 'hello from windows' -NoNewline
  Set-Content -Path "$src\Documents\Über Ordner\日本語 ünïcödé.txt" -Value 'unicode content' -Encoding UTF8
  $rnd = New-Object byte[] (12MB); (New-Object Random 42).NextBytes($rnd)
  [IO.File]::WriteAllBytes("$src\big.bin", $rnd)
  Set-Content "$src\hidden.txt" 'hidden'; attrib +h "$src\hidden.txt"
  Set-Content "$src\system.txt" 'system'; attrib +s "$src\system.txt"
  Set-Content "$src\readonly.txt" 'readonly'; attrib +r "$src\readonly.txt"
  $old = Get-Date '2019-03-04T05:06:07'
  Set-Content "$src\dated.txt" 'old file'
  (Get-Item "$src\dated.txt").CreationTime = $old.AddDays(-30)
  (Get-Item "$src\dated.txt").LastWriteTime = $old
  # long path (> 260 chars)
  $long = $src; foreach ($n in 1..12) { $long = Join-Path $long ('very-long-directory-name-' + $n) }
  New-Item -ItemType Directory -Force -Path "\\?\$long" | Out-Null
  [IO.File]::WriteAllText("\\?\$long\deep.txt", 'deep file')
  # alternate data streams: small ones are kept, ones over 64 KiB skipped with a warning
  Set-Content -Path "$src\ads.txt" -Value 'main stream'; Set-Content -Path "$src\ads.txt" -Stream 'secret' -Value 'ads'
  Set-Content -Path "$src\ads.txt" -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3"
  [IO.File]::WriteAllBytes("$src\ads.txt:huge", (New-Object byte[] (100KB)))
  New-Item -ItemType Directory -Force -Path "$src\ads dir" | Out-Null
  Set-Content -Path "$src\ads dir" -Stream 'dirstream' -Value 'on a folder'
  # NTFS ACLs: an explicit ACE on a file, a protected folder with its own DACL
  Set-Content "$src\acl.txt" 'acl'
  icacls "$src\acl.txt" /grant '*S-1-5-32-545:(R,W)' | Out-Null
  New-Item -ItemType Directory -Force -Path "$src\private" | Out-Null
  Set-Content "$src\private\inner.txt" 'inner'
  icacls "$src\private" /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
  # symlink + junction
  cmd /c "mklink `"$src\link-to-readme.txt`" `"Documents\readme.txt`"" | Out-Null
  cmd /c "mklink /J `"$src\junction-to-windows`" `"C:\Windows`"" | Out-Null
  # locked file: held open without sharing during the backup (only VSS can read it)
  Set-Content "$src\locked.db" 'locked database content'
  $lock = [IO.File]::Open("$src\locked.db", 'Open', 'ReadWrite', 'None')

  # ---------- file backup with VSS ----------
  $r = RunAgent (@('backup') + $common + @('-source', $src, '-vss=true'))
  $lock.Close()
  $results.backup_output = $r.text
  Check 'file backup succeeded' ($r.json -and $r.json.state -in 'success','warning') $r.json.state
  Check 'VSS snapshot used' ($r.text -match 'VSS snapshot .* ready') ''
  Check 'locked file read via VSS (not skipped)' ($r.text -notmatch 'skipped .*locked\.db') ''
  Check 'junction not followed' ($r.text -match 'junction-to-windows') 'logged as special file'
  $snapTime = [int64]$r.json.backup_time

  # ---------- restore ----------
  $dst = Join-Path $Work 'restore'
  $label = ($src.ToLower() -replace '[:\\]+', '-').Trim('-') -replace '[^a-z0-9_.-]', '-'
  $r2 = RunAgent (@('restore') + $common + @('-time', "$snapTime", '-archive', "$label.pxar.didx", '-target', $dst, '-overwrite', 'overwrite'))
  $results.restore_output = $r2.text
  Check 'restore succeeded' ($r2.json -and $r2.json.state -eq 'success') $r2.json.state

  function H($p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }
  foreach ($f in 'big.bin','Documents\readme.txt','Documents\Über Ordner\日本語 ünïcödé.txt','locked.db','hidden.txt','dated.txt') {
    $a = Join-Path $src $f; $b = Join-Path $dst $f
    Check "content: $f" ((Test-Path -LiteralPath $b) -and (H $a) -eq (H $b))
  }
  Check 'long path restored' ([IO.File]::Exists("\\?\" + ($long.Replace($src, $dst)) + '\deep.txt'))
  $ga = { param($p) (Get-Item -LiteralPath $p -Force).Attributes }
  Check 'hidden attribute' ((& $ga "$dst\hidden.txt") -band [IO.FileAttributes]::Hidden)
  Check 'system attribute' ((& $ga "$dst\system.txt") -band [IO.FileAttributes]::System)
  Check 'readonly attribute' ((& $ga "$dst\readonly.txt") -band [IO.FileAttributes]::ReadOnly)
  $d = Get-Item "$dst\dated.txt"
  Check 'LastWriteTime preserved' ($d.LastWriteTime -eq $old) $d.LastWriteTime.ToString('o')
  Check 'CreationTime preserved' ($d.CreationTime -eq $old.AddDays(-30)) $d.CreationTime.ToString('o')
  $l = Get-Item "$dst\link-to-readme.txt" -Force
  Check 'symlink restored as symlink' ($l.LinkType -eq 'SymbolicLink') "$($l.LinkType) -> $($l.Target)"
  Check 'junction not restored' (-not (Test-Path "$dst\junction-to-windows"))
  Check 'empty dir restored' (Test-Path "$dst\empty dir")
  $ads = { param($p, $n) (Get-Content -LiteralPath $p -Stream $n -ErrorAction SilentlyContinue) -join "`n" }
  Check 'ADS restored' ((& $ads "$dst\ads.txt" 'secret') -eq 'ads') (& $ads "$dst\ads.txt" 'secret')
  Check 'Zone.Identifier restored' ((& $ads "$dst\ads.txt" 'Zone.Identifier') -match 'ZoneId=3')
  Check 'folder ADS restored' ((& $ads "$dst\ads dir" 'dirstream') -eq 'on a folder')
  Check 'large ADS skipped with warning' ((-not (Get-Item -LiteralPath "$dst\ads.txt" -Stream huge -ErrorAction SilentlyContinue)) -and $r.text -match 'stream "huge"')
  Check 'main stream intact with ADS' ((Get-Content -LiteralPath "$dst\ads.txt") -eq 'main stream')
  $sddl = { param($p) (Get-Acl -LiteralPath $p).Sddl }
  foreach ($f in 'acl.txt', 'private', 'private\inner.txt', 'Documents') {
    $a = & $sddl (Join-Path $src $f); $b = & $sddl (Join-Path $dst $f)
    Check "ACL: $f" ($a -eq $b) $b
  }
  Check 'protected folder stays protected' ((Get-Acl -LiteralPath "$dst\private").AreAccessRulesProtected)

  # ---------- incremental ----------
  $r3 = RunAgent (@('backup') + $common + @('-source', $src, '-vss=true'))
  Check 'incremental backup reuses chunks' ($r3.json -and $r3.json.chunks_reused -gt 0 -and $r3.json.chunks_new -le 1) "new=$($r3.json.chunks_new) reused=$($r3.json.chunks_reused)"

  # ---------- volume image of a small VHDX ----------
  if (-not $SkipImage) {
    $vhd = Join-Path $Work 'vol.vhdx'
    $letter = (68..90 | ForEach-Object { [char]$_ } | Where-Object { -not (Test-Path "$($_):\") } | Select-Object -Last 1)
    @"
create vdisk file="$vhd" maximum=256 type=expandable
select vdisk file="$vhd"
attach vdisk
create partition primary
format fs=ntfs quick label=PROXBACKUPTEST
assign letter=$letter
"@ | Set-Content "$Work\dp.txt" -Encoding ASCII
    diskpart /s "$Work\dp.txt" | Out-Null
    $marker = 'PROXBACKUP-IMAGE-MARKER-' + [guid]::NewGuid()
    Set-Content "$($letter):\marker.txt" $marker
    $r4 = RunAgent (@('image') + $common + @('-id', "$Id-image", '-source', "$($letter):"))
    $results.image_output = $r4.text
    Check 'image backup succeeded' ($r4.json -and $r4.json.state -eq 'success') "$($r4.json.state) $($r4.json.bytes_total) bytes"
    $iarch = "drive-$($letter.ToString().ToLower()).img.fidx"
    $r5 = RunAgent (@('restore') + $common + @('-id', "$Id-image", '-time', "$($r4.json.backup_time)", '-archive', $iarch, '-target', "$Work\imgrestore"))
    $img = Get-ChildItem "$Work\imgrestore\*.img" | Select-Object -First 1
    $bytes = if ($img) { [IO.File]::ReadAllBytes($img.FullName) } else { @() }
    Check 'image restored, NTFS boot sector' ($img -and [Text.Encoding]::ASCII.GetString($bytes, 3, 4) -eq 'NTFS') "$($img.Length) bytes"
    Check 'image contains file written before backup' ([Text.Encoding]::ASCII.GetString($bytes).Contains($marker))
    "select vdisk file=`"$vhd`"`ndetach vdisk" | Set-Content "$Work\dp2.txt" -Encoding ASCII
    diskpart /s "$Work\dp2.txt" | Out-Null
  }
} catch {
  $results.errors += "$($_.Exception.Message) at $($_.InvocationInfo.PositionMessage)"
  Write-Host "ERROR: $_"
}
$results.finished = (Get-Date).ToString('o')
$results.passed = @($results.checks.Values | Where-Object { $_.ok }).Count
$results.failed = @($results.checks.Values | Where-Object { -not $_.ok }).Count + $results.errors.Count
$results | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Work 'results.json') -Encoding UTF8
Write-Host "passed=$($results.passed) failed=$($results.failed)"
