$ErrorActionPreference = 'Stop'
$vhd = 'C:\proxbackup-test\ntfs-test.vhd'
if (Test-Path $vhd) { "select vdisk file=$vhd`ndetach vdisk" | Set-Content -Encoding ascii C:\proxbackup-test\dp0.txt; diskpart /s C:\proxbackup-test\dp0.txt | Out-Null; Remove-Item $vhd -Force }
@"
create vdisk file=$vhd maximum=40 type=fixed
select vdisk file=$vhd
attach vdisk
create partition primary
format fs=ntfs quick label=PBTEST unit=4096
assign letter=T
"@ | Set-Content -Encoding ascii C:\proxbackup-test\dp1.txt
diskpart /s C:\proxbackup-test\dp1.txt | Out-Null
$r = 'T:\'
function Pat([int]$n, [int]$seed) { $b = New-Object byte[] $n; for ($i=0; $i -lt $n; $i++) { $b[$i] = [byte](($i * 7 + $seed + [math]::Floor($i / 4096)) % 251) }; return ,$b }
New-Item -ItemType Directory "$r\docs\deep\er\still" | Out-Null
[IO.File]::WriteAllText("$r\docs\small.txt", 'hello ntfs')
[IO.File]::WriteAllBytes("$r\docs\deep\er\still\nested.bin", (Pat 70000 3))
New-Item -ItemType File "$r\docs\empty.txt" | Out-Null
$rnd = New-Object byte[] 300000; (New-Object Random 42).NextBytes($rnd); [IO.File]::WriteAllBytes("$r\random.bin", $rnd)
# unicode name
$un = "U" + [char]0x308 + "n" + [char]0xEF + "c" + [char]0xF8 + "d" + [char]0xE9 + " " + [char]0x6587 + [char]0x4EF6 + ".txt"; [IO.File]::WriteAllText("$r\docs\$un", "unicode")
# many files -> index allocation
New-Item -ItemType Directory "$r\many" | Out-Null
for ($i=0; $i -lt 400; $i++) { [IO.File]::WriteAllText("$r\many\file-with-a-longish-name-$i.txt", "content $i") }
# compressed
New-Item -ItemType Directory "$r\comp" | Out-Null
[IO.File]::WriteAllBytes("$r\comp\compressed.bin", (Pat 500000 9))
compact /c "$r\comp\compressed.bin" | Out-Null
# sparse
$sp = "$r\sparse.bin"
$f = [IO.File]::Create($sp); $f.Close()
fsutil sparse setflag $sp | Out-Null
$fs = [IO.File]::OpenWrite($sp); $fs.SetLength(3MB); $fs.Seek(2MB, 'Begin') | Out-Null; $d = Pat 8192 5; $fs.Write($d, 0, $d.Length); $fs.Close()
fsutil sparse setrange $sp 0 2097152 | Out-Null
fsutil sparse setrange $sp 2105344 1040384 | Out-Null
# fragmented: fill with chunks, delete every other, write a big file
New-Item -ItemType Directory "$r\filler" | Out-Null
$fill = Pat 65536 1
for ($i=0; $i -lt 200; $i++) { [IO.File]::WriteAllBytes("$r\filler\f$i.bin", $fill) }
$free = (Get-PSDrive T).Free - 4MB
$fs = [IO.File]::Create("$r\hog.bin"); $fs.SetLength($free); $fs.Close()
for ($i=0; $i -lt 200; $i+=2) { Remove-Item "$r\filler\f$i.bin" }
$fs = [IO.File]::Create("$r\fragmented.bin"); for ($i=0; $i -lt 90; $i++) { $d = Pat 65536 (100+$i); $fs.Write($d,0,$d.Length) }; $fs.Close()
Remove-Item "$r\hog.bin"
# hard links -> attribute list
New-Item -ItemType Directory "$r\links" | Out-Null
[IO.File]::WriteAllText("$r\links\target.txt", 'linked')
for ($i=0; $i -lt 120; $i++) { fsutil hardlink create "$r\links\hardlink-number-$i-with-a-long-name.txt" "$r\links\target.txt" | Out-Null }
# ADS, junction, attributes
cmd /c "echo stream> T:\docs\small.txt:extra"
cmd /c mklink /J "$r\junction" "$r\docs" | Out-Null
[IO.File]::WriteAllText("$r\docs\hidden-ro.txt", 'attrs')
(Get-Item "$r\docs\hidden-ro.txt").Attributes = 'Hidden,ReadOnly'
(Get-Item "$r\docs\small.txt").LastWriteTimeUtc = [datetime]::new(2020,1,2,3,4,5,[DateTimeKind]::Utc)
# manifest
$out = @()
Get-ChildItem -Recurse -File -Force $r -Attributes !ReparsePoint | Where-Object { $_.FullName -notlike '*System Volume Information*' -and $_.FullName -notlike 'T:\junction*' } | ForEach-Object {
  $out += [pscustomobject]@{ path = $_.FullName.Substring(3).Replace('\','/'); size = $_.Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLower(); attrs = [int]$_.Attributes; mtime = ([DateTimeOffset]$_.LastWriteTimeUtc).ToUnixTimeSeconds() }
}
$out | ConvertTo-Json -Depth 3 | Set-Content -Encoding utf8 C:\proxbackup-test\ntfs-test.json
fsutil file queryextents "$r\fragmented.bin" | Measure-Object -Line
@"
select vdisk file=$vhd
detach vdisk
"@ | Set-Content -Encoding ascii C:\proxbackup-test\dp2.txt
diskpart /s C:\proxbackup-test\dp2.txt | Out-Null
'done'
