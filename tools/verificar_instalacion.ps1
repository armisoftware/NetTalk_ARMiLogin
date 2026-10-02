# verificar_instalacion.ps1
# Compara todas las copias de NetTalk_ARMiLogin instaladas en un Clarion con los archivos maestros.
# Uso:  powershell -File verificar_instalacion.ps1 -Target C:\Clarion12SymbolicNT14 [-Master C:\Clarion111-NT14] [-ExeWeb C:\...\NetPack12\Exe\web]
# No modifica nada: solo lee y muestra.
param(
  [string]$Target = 'C:\Clarion12SymbolicNT14',
  [string]$Master = 'C:\Clarion111-NT14',
  [string]$ExeWeb = ''
)

# archivo maestro  -> carpeta del Clarion donde esta el maestro
$masters = [ordered]@{
  'NetTalk_ARMiLogin.tpl' = "$Master\accessory\template\win"
  'NetTalk_ARMiLogin.tpw' = "$Master\accessory\template\win"
  'NetTalk_ARMiLogin.inc' = "$Master\accessory\libsrc\win"
  'NetTalk_ARMiLogin.clw' = "$Master\accessory\libsrc\win"
  'NetTalk_ARMiLogin.js'  = "$Master\accessory\libsrc\win"
  'bcrypt.lib'            = "$Master\accessory\lib"
}

$bad = 0
foreach ($name in $masters.Keys) {
  $mp = Join-Path $masters[$name] $name
  if (-not (Test-Path $mp)) { Write-Host ("{0,-24} MAESTRO NO ENCONTRADO: {1}" -f $name, $mp) -ForegroundColor Yellow; continue }
  $mh = (Get-FileHash $mp -Algorithm SHA256).Hash
  Write-Host ("`n{0}   (maestro {1}, {2} bytes, {3})" -f $name, (Get-Item $mp).LastWriteTime.ToString('MM-dd HH:mm:ss'), (Get-Item $mp).Length, $mh.Substring(0,8))
  $copies = Get-ChildItem $Target -Recurse -File -Filter $name -ErrorAction SilentlyContinue
  if (-not $copies) { Write-Host "   NO esta instalado en $Target" -ForegroundColor Red; $bad++; continue }
  foreach ($c in $copies) {
    $h = (Get-FileHash $c.FullName -Algorithm SHA256).Hash
    $rel = $c.DirectoryName.Substring($Target.Length).TrimStart('\')
    if ($h -eq $mh) { Write-Host ("   OK        {0,-34} {1}" -f $rel, $c.LastWriteTime.ToString('MM-dd HH:mm:ss')) -ForegroundColor Green }
    else            { Write-Host ("   DISTINTO  {0,-34} {1}  {2} bytes" -f $rel, $c.LastWriteTime.ToString('MM-dd HH:mm:ss'), $c.Length) -ForegroundColor Red; $bad++ }
  }
}

if ($ExeWeb -ne '') {
  Write-Host "`nCopia del script en la carpeta web del ejecutable:"
  $js = Join-Path $ExeWeb 'scripts\NetTalk_ARMiLogin.js'
  $mj = (Get-FileHash "$Master\accessory\libsrc\win\NetTalk_ARMiLogin.js").Hash
  if (-not (Test-Path $js)) { Write-Host "   NO existe: $js" -ForegroundColor Red; $bad++ }
  elseif ((Get-FileHash $js).Hash -eq $mj) { Write-Host ("   OK        {0}  {1}" -f $js, (Get-Item $js).LastWriteTime.ToString('MM-dd HH:mm:ss')) -ForegroundColor Green }
  else { Write-Host "   DISTINTO  $js" -ForegroundColor Red; $bad++ }
}

Write-Host ""
if ($bad -eq 0) { Write-Host "Todo coincide con los maestros." -ForegroundColor Green } else { Write-Host "$bad problema(s): hay copias faltantes o distintas del maestro." -ForegroundColor Red }
