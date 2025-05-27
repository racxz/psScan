# Run this in an elevated PowerShell (as Administrator)

# Function to check if file is signed
function Get-SignatureStatus {
    param ($path)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $path
        if ($signature.Status -eq 'Valid') { return "Signed - $($signature.SignerCertificate.Subject)" }
        else { return "Unsigned or Invalid" }
    } catch { return "Error checking signature" }
}

# Get all PE (MZ) files dropped in common suspicious paths
$SuspiciousPaths = @("$env:APPDATA", "$env:LOCALAPPDATA", "$env:TEMP", "$env:USERPROFILE\Downloads", "$env:PUBLIC", "C:\ProgramData", "C:\$Recycle.Bin")
Write-Host "`n🔎 Scanning for dropped PE files (MZ headers)..." -ForegroundColor Cyan
foreach ($dir in $SuspiciousPaths) {
    if (Test-Path $dir) {
        Get-ChildItem -Path $dir -Recurse -ErrorAction SilentlyContinue -File | ForEach-Object {
            try {
                $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
                if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
                    $sig = Get-SignatureStatus -path $_.FullName
                    [PSCustomObject]@{
                        Path = $_.FullName
                        LastWriteTime = $_.LastWriteTime
                        Signature = $sig
                    }
                }
            } catch {}
        }
    }
}

# List non-Microsoft scheduled tasks
Write-Host "`n⏱️ Scanning scheduled tasks outside Microsoft..." -ForegroundColor Cyan
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' } | ForEach-Object {
    [PSCustomObject]@{
        TaskName = $_.TaskName
        TaskPath = $_.TaskPath
        Author = $_.Principal.UserId
        Action = ($_ | Get-ScheduledTaskInfo).LastRunTime
    }
}

# List autostart services with suspicious paths
Write-Host "`n🔧 Analyzing autostart services with suspicious paths..." -ForegroundColor Cyan
Get-WmiObject win32_service | Where-Object {
    $_.StartMode -eq "Auto" -and
    ($_.PathName -like "*AppData*" -or $_.PathName -like "*Temp*" -or $_.PathName -notlike "*System32*")
} | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Name
        Path = $_.PathName
        State = $_.State
        Signature = Get-SignatureStatus -path ($_ | Select-String -Pattern '"(.*?)"' | ForEach-Object { $_.Matches.Groups[1].Value } )
    }
}

# [Optional] Network connections from unsigned binaries
Write-Host "`n🌐 Mapping unsigned running processes with network activity..." -ForegroundColor Cyan
$procs = Get-Process | Where-Object { $_.Path -and (Get-SignatureStatus $_.Path) -notmatch "Signed" }
foreach ($proc in $procs) {
    $connections = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue
    foreach ($conn in $connections) {
        [PSCustomObject]@{
            ProcessName = $proc.Name
            PID = $proc.Id
            Path = $proc.Path
            RemoteAddress = $conn.RemoteAddress
            RemotePort = $conn.RemotePort
            State = $conn.State
        }
    }
}
