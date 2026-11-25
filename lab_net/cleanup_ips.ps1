<#
.SYNOPSIS
    Gỡ toàn bộ các IP phụ (IP Alias) đã thêm từ file source_ips.txt.
    Chạy bằng PowerShell với quyền Administrator sau khi demo/test xong.
#>
param(
    [string]$AdapterName = "",
    [string]$InputFile = "$PSScriptRoot\source_ips.txt"
)

if (-not (Test-Path $InputFile)) {
    Write-Error "Không tìm thấy file $InputFile"
    exit 1
}

if (-not $AdapterName) {
    $adapter = Get-NetAdapter | Where-Object {
        $_.Status -eq "Up" -and ($_.Name -like "*VMnet1*" -or $_.InterfaceDescription -like "*VMnet1*" -or $_.Name -like "*Host-Only*")
    } | Select-Object -First 1
    if (-not $adapter) {
        Write-Error "Không tìm thấy card mạng Host-only."
        exit 1
    }
    $AdapterName = $adapter.Name
}

$ips = Get-Content $InputFile | Where-Object { $_.Trim() -ne "" -and $_.Trim() -ne "127.0.0.1" }
foreach ($ip in $ips) {
    $existing = Get-NetIPAddress -InterfaceAlias $AdapterName -IPAddress $ip -ErrorAction SilentlyContinue
    if ($existing) {
        Remove-NetIPAddress -InterfaceAlias $AdapterName -IPAddress $ip -Confirm:$false
        Write-Host "  [-] Đã gỡ IP phụ: $ip" -ForegroundColor Yellow
    }
}
Write-Host "[*] Hoàn tất dọn dẹp IP phụ trên $AdapterName." -ForegroundColor Cyan
