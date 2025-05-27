# Requires admin rights

# Your VirusTotal API key here
$VT_API_KEY = "YOUR_VT_API_KEY_HERE"

# Output files
$timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$jsonLogPath = "$env:USERPROFILE\Desktop\ThreatHuntLog_$timestamp.json"
$csvLogPath = "$env:USERPROFILE\Desktop\ThreatHuntLog_$timestamp.csv"

# Function to compute SHA256 hash
function Get-FileHashSHA256 {
    param ($path)
    try {
        return (Get-FileHash -Path $path -Algorithm SHA256).Hash
    } catch {
        return $null
    }
}

# Function to check if file is signed
function Get-SignatureStatus {
    param ($path)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $path
        if ($signature.Status -eq 'Valid') { return "Signed - $($signature.SignerCertificate.Subject)" }
        else { return "Unsigned or Invalid" }
    } catch { return "Error checking signature" }
}

# Function to query VirusTotal
function Get-VirusTotalReport {
    param ($sha256)

    if (-not $sha256) { return $null }
    $uri = "https://www.virustotal.com/api/v3/files/$sha256"
    $headers = @{ "x-apikey" = $VT_API_KEY }

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -ErrorAction Stop
        $data = $response.data
        $maliciousCount = $data.attributes.last_analysis_stats.malicious
        $totalCount = ($data.attributes.last_analysis_stats.malicious + $data.attributes.last_analysis_stats.harmless + $data.attributes.last_analysis_stats.suspicious + $data.attributes.last_analysis_stats.timeout + $data.attributes.last_analysis_stats.failure)
        $scanDate = $data.attributes.last_analysis_date | ForEach-Object { [DateTime]::UnixEpoch.AddSeconds($_) }
        return [PSCustomObject]@{
            SHA256 = $sha256
            Malicious = $maliciousCount
            TotalEngines = $totalCount
            ScanDate = $scanDate
            VTLink = "https://www.virustotal.com/gui/file/$sha256/detection"
        }
    } catch {
        return [PSCustomObject]@{
            SHA256 = $sha256
            Malicious = "Error or Not Found"
            TotalEngines = 0
            ScanDate = $null
            VTLink = ""
        }
    }
}

# Store results
$results = @()

# Paths to scan
$SuspiciousPaths = @("$env:APPDATA", "$env:LOCALAPPDATA", "$env:TEMP", "$env:USERPROFILE\Downloads", "$env:PUBLIC", "C:\ProgramData", "C:\$Recycle.Bin")

Write-Host "`n🔎 Scanning dropped PE files (MZ headers) for suspicious files..." -ForegroundColor Cyan
foreach ($dir in $SuspiciousPaths) {
    if (Test-Path $dir) {
        Get-ChildItem -Path $dir -Recurse -ErrorAction SilentlyContinue -File | ForEach-Object {
            try {
                $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
                if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
                    $sigStatus = Get-SignatureStatus -path $_.FullName
                    $sha256 = Get-FileHashSHA256 -path $_.FullName
                    $vtReport = Get-VirusTotalReport -sha256 $sha256

                    $obj = [PSCustomObject]@{
                        Type = "Dropped PE File"
                        Path = $_.FullName
                        LastWriteTime = $_.LastWriteTime
                        Signature = $sigStatus
                        SHA256 = $sha256
                        VT_Malicious = $vtReport.Malicious
                        VT_TotalEngines = $vtReport.TotalEngines
                        VT_ScanDate = $vtReport.ScanDate
                        VT_Link = $vtReport.VTLink
                    }
                    $results += $obj
                    Write-Host "Found PE: $($_.FullName) - $sigStatus - Malicious VT detections: $($vtReport.Malicious)" -ForegroundColor Yellow
                }
            } catch {}
        }
    }
}

Write-Host "`n⏱️ Checking scheduled tasks outside Microsoft..." -ForegroundColor Cyan
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' } | ForEach-Object {
    $taskName = $_.TaskName
    $taskPath = $_.TaskPath
    $author = $_.Principal.UserId
    $lastRun = ($_ | Get-ScheduledTaskInfo).LastRunTime

    $obj = [PSCustomObject]@{
        Type = "Scheduled Task"
        TaskName = $taskName
        TaskPath = $taskPath
        Author = $author
        LastRunTime = $lastRun
    }
    $results += $obj
}

Write-Host "`n🔧 Analyzing autostart services with suspicious paths..." -ForegroundColor Cyan
Get-WmiObject win32_service | Where-Object {
    $_.StartMode -eq "Auto" -and
    ($_.PathName -like "*AppData*" -or $_.PathName -like "*Temp*" -or $_.PathName -notlike "*System32*")
} | ForEach-Object {
    $name = $_.Name
    $path = $_.PathName
    $state = $_.State
    $exePath = ($_ | Select-String -Pattern '"(.*?)"' | ForEach-Object { $_.Matches.Groups[1].Value }) -join ""
    $sig = if ($exePath) { Get-SignatureStatus -path $exePath } else { "Unknown" }
    $sha256 = if ($exePath) { Get-FileHashSHA256 -path $exePath } else { $null }
    $vtReport = if ($sha256) { Get-VirusTotalReport -sha256 $sha256 } else { $null }

    $obj = [PSCustomObject]@{
        Type = "Auto Service"
        Name = $name
        Path = $path
        State = $state
        Signature = $sig
        SHA256 = $sha256
        VT_Malicious = if ($vtReport) { $vtReport.Malicious } else { "" }
        VT_TotalEngines = if ($vtReport) { $vtReport.TotalEngines } else { "" }
        VT_ScanDate = if ($vtReport) { $vtReport.ScanDate } else { "" }
        VT_Link = if ($vtReport) { $vtReport.VTLink } else { "" }
    }
    $results += $obj
}

# Optional: You can add network connections part here if you want

# Export to JSON & CSV
Write-Host "`n💾 Exporting results to JSON and CSV on your Desktop..." -ForegroundColor Green
$results | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonLogPath -Encoding UTF8
$results | Export-Csv -Path $csvLogPath -NoTypeInformation -Encoding UTF8

Write-Host "`n✅ Scan complete! Logs saved here:" -ForegroundColor Green
Write-Host "JSON: $jsonLogPath"
Write-Host "CSV:  $csvLogPath"
Write-Host "`n🔗 VirusTotal links included for suspicious files where applicable." -ForegroundColor Cyan
