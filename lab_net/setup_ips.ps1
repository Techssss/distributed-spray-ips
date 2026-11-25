<#
.SYNOPSIS
    Thêm nhiều IP phụ (IP Alias) trên card mạng Host-only (VMnet1 hoặc VirtualBox Host-Only)
    để Windows gửi request từ nhiều IP nguồn khác nhau sang Kali VM.
    Chạy bằng PowerShell với quyền Administrator.
#>
param(
    [string]$AdapterName = "",
    [int]$StartHostOctet = 101,
    [int]$Count = 12,
    [string]$OutputFile = "$PSScriptRoot\source_ips.txt"
)

if (-not $AdapterName) {
    $adapter = Get-NetAdapter | Where-Object {
        $_.Status -eq "Up" -and ($_.Name -like "*VMnet1*" -or $_.InterfaceDescription -like "*VMnet1*" -or $_.Name -like "*Host-Only*")
    } | Select-Object -First 1
    if (-not $adapter) {
        Write-Error "Không tìm thấy card mạng Host-only. Hãy truyền tham số -AdapterName '<tên card>'."
        exit 1
    }
    $AdapterName = $adapter.Name
}

$primaryIpObj = Get-NetIPAddress -InterfaceAlias $AdapterName -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike "169.254.*" } |
    Select-Object -First 1

if (-not $primaryIpObj) {
    Write-Error "Card '$AdapterName' chưa có địa chỉ IPv4 hợp lệ."
    exit 1
}

$octets = $primaryIpObj.IPAddress.Split(".")
$subnetPrefix = "$($octets[0]).$($octets[1]).$($octets[2])"
$prefixLen = $primaryIpObj.PrefixLength

# Đảm bảo IP gốc .1 luôn tồn tại với SkipAsSource = $false (tránh mất IP mặc định cho trình duyệt sau khi reboot)
$hostDefaultIp = "$subnetPrefix.1"
$existingHostIp = Get-NetIPAddress -InterfaceAlias $AdapterName -IPAddress $hostDefaultIp -ErrorAction SilentlyContinue
if (-not $existingHostIp) {
    New-NetIPAddress -InterfaceAlias $AdapterName -IPAddress $hostDefaultIp -PrefixLength $prefixLen -SkipAsSource $false | Out-Null
    Write-Host "  [+] Đã khôi phục IP chính cho trình duyệt/host: $hostDefaultIp/$prefixLen" -ForegroundColor Green
} elseif ($existingHostIp.SkipAsSource) {
    Set-NetIPAddress -InterfaceAlias $AdapterName -IPAddress $hostDefaultIp -SkipAsSource $false | Out-Null
}

Write-Host "[*] Đang dùng card: $AdapterName (IP chính: $hostDefaultIp/$prefixLen)" -ForegroundColor Cyan

$ipsToSave = @()
for ($i = 0; $i -lt $Count; $i++) {
    $ip = "$subnetPrefix.$($StartHostOctet + $i)"
    $existing = Get-NetIPAddress -InterfaceAlias $AdapterName -IPAddress $ip -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  [=] IP $ip đã tồn tại, bỏ qua." -ForegroundColor Yellow
    } else {
        New-NetIPAddress -InterfaceAlias $AdapterName -IPAddress $ip -PrefixLength $prefixLen -SkipAsSource $true | Out-Null
        Write-Host "  [+] Đã thêm IP phụ: $ip/$prefixLen" -ForegroundColor Green
    }
    $ipsToSave += $ip
}

$ipsToSave | Set-Content -Path $OutputFile -Encoding UTF8
Write-Host "[*] Đã lưu $($ipsToSave.Count) IP nguồn vào: $OutputFile" -ForegroundColor Cyan
