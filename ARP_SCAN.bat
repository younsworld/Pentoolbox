@echo off
setlocal
set RANGE=%1
if "%RANGE%"=="" set RANGE=192.168.1.0/24
set URL=%2
if "%URL%"=="" set URL=http://localhost:5000

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"$range='%RANGE%'; $url='%URL%'; $base=($range -split '/')[0] -replace '\.\d+$',''; $start=[DateTime]::Now; $results=1..254 | ForEach-Object { $ip=\"$base.$_\"; $ping=New-Object System.Net.NetworkInformation.Ping; try { $r=$ping.Send($ip,500); if($r.Status -eq 'Success'){ try{$h=[System.Net.Dns]::GetHostEntry($ip).HostName}catch{$h='?'}; \"$ip|$($r.RoundtripTime)|$h\" } } catch {} } | Where-Object {$_}; $elapsed=[math]::Round(([DateTime]::Now-$start).TotalSeconds,2); $out=\"[*] ARP Scan Windows (PowerShell) → $range\`n[*] Duree: ${elapsed}s\`n\" + ('─'*50) + \"\`n\"; $count=0; foreach($r in ($results|Sort-Object)){$p=$r-split'\|';$out+=\"[+] $($p[0].PadRight(18)) $($p[1])ms  $($p[2])\`n\";$count++}; $out+=('─'*50)+\"\`n[OK] $count hote(s) actif(s) sur $range - $($elapsed)s\"; $body=@{scan_id='arp_win';output=$out}|ConvertTo-Json -Compress; try{Invoke-RestMethod -Uri \"$url/api/arp/windows_results\" -Method POST -Body $body -ContentType 'application/json' -TimeoutSec 5}catch{Write-Host 'Erreur envoi'}"
