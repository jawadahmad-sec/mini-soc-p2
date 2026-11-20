Write-Host "Starting Windows MITRE Scenarios (S3, S4, S5)..." -ForegroundColor Cyan

# S3: Failed Logins
Write-Host "[S3] Generating Failed Logins..."
for ($i=1; $i -le 5; $i++) {
    $fakeUser = "FakeUser_$i"
    $securePass = ConvertTo-SecureString "FakePassword123!" -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($fakeUser, $securePass)
    Start-Process -FilePath "cmd.exe" -Credential $cred -ErrorAction SilentlyContinue
}

# S4: PowerShell Execution
Write-Host "[S4] Executing PowerShell..."
Start-Process powershell -ArgumentList "Get-Process | Out-File C:\Windows\Temp\ps-test.txt" -Wait

# S5: File Modification
Write-Host "[S5] Modifying Startup folder..."
New-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\fyp-test.txt" -ItemType File -Force
Start-Sleep -Seconds 2
Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\fyp-test.txt" -Force

Write-Host "Windows Scenarios Completed!" -ForegroundColor Green
