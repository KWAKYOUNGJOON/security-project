$content = Get-Content -Path '02.Windows서버_run_all.ps1' -Raw -Encoding UTF8
$Utf8BomEncoding = New-Object System.Text.UTF8Encoding $True
[System.IO.File]::WriteAllText('02.Windows서버_run_all.ps1', $content, $Utf8BomEncoding)
Write-Host "File saved with UTF-8 BOM"
