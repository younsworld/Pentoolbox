# PenToolbox v4.0 - ARP Scan Windows
# Lance ce script pour scanner le reseau depuis Windows
# Les resultats sont envoyes automatiquement a PenToolbox

param(
    [string]$Range = "192.168.1.0/24",
    [string]$PenToolboxUrl = "http://localhost:5000"
)

Write-Host ""
Write-Host "  ================================================="
Write-Host "   PenToolbox - ARP Scan Windows (PowerShell)"
Write-Host "  ================================================="
Write-Host ""
Write-Host "  [*] Cible    : $Range"
Write-Host "  [*] Methode  : Ping sweep PowerShell parallel"
Write-Host ""

# Extrait la base d'IP depuis le CIDR
$base = ($Range -split "/")[0] -replace "\.\d+$",""
$start = [DateTime]::Now

Write-Host "  [*] Scan en cours... (peut prendre 30-60 secondes)"
Write-Host ""

# Ping sweep parallele
$jobs = 1..254 | ForEach-Object {
    $ip = "$base.$_"
    Start-Job -ScriptBlock {
        param($ip)
        $ping = New-Object System.Net.NetworkInformation.Ping
        try {
            $reply = $ping.Send($ip, 500)
            if ($reply.Status -eq "Success") {
                # Essaie de resoudre le hostname
                try { $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName }
                catch { $hostname = "?" }
                "$ip|$($reply.RoundtripTime)|$hostname"
            }
        } catch {}
    } -ArgumentList $ip
}

$results = $jobs | Wait-Job | Receive-Job | Where-Object { $_ -ne $null } | Sort-Object

# Formate les resultats
$output = "[*] ARP Scan Windows (PowerShell) → $Range`n"
$output += "[*] Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
$output += "─" * 56 + "`n"
$output += "[*] IP ADDRESS          LATENCY   HOSTNAME`n"
$output += "─" * 56 + "`n"

$count = 0
foreach ($r in $results) {
    $parts = $r -split "\|"
    $ip = $parts[0]; $ms = $parts[1]; $host = $parts[2]
    $line = "[+] $($ip.PadRight(20)) $("${ms}ms".PadRight(10)) $host"
    $output += "$line`n"
    Write-Host "  $line"
    $count++
}

$elapsed = ([DateTime]::Now - $start).TotalSeconds
$output += "─" * 56 + "`n"
$output += "[OK] Scan termine - $count hote(s) actif(s) sur $Range`n"
$output += "[*] Duree: $([math]::Round($elapsed, 2))s"

Write-Host ""
Write-Host "  ─────────────────────────────────────────────────"
Write-Host "  [OK] $count hote(s) trouve(s) en $([math]::Round($elapsed, 2))s"
Write-Host ""

# Envoie les resultats a PenToolbox
$scan_id = [System.Guid]::NewGuid().ToString()
$body = @{
    scan_id = $scan_id
    output  = $output
} | ConvertTo-Json -Compress

try {
    $response = Invoke-RestMethod -Uri "$PenToolboxUrl/api/arp/windows_results" `
        -Method POST -Body $body -ContentType "application/json" -TimeoutSec 5
    Write-Host "  [OK] Resultats envoyes a PenToolbox !"
    Write-Host "  [*] Retournez sur http://localhost:5000 → ARP Scan"
} catch {
    Write-Host "  [!] Impossible d'envoyer a PenToolbox: $_"
    Write-Host "  [*] Copiez les resultats ci-dessus manuellement"
}

Write-Host ""
Write-Host "  ================================================="
Read-Host "  Appuyez sur Entree pour fermer"
