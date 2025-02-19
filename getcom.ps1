$Tasks = Get-ScheduledTask
foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      $usersSid = "S-1-5-32-545"
      $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }
      if ($Task.Principal.GroupId -eq $usersGroup)
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        $clsid = $Task.Actions.ClassId
        Write-Host "CLSID: " $clsid
        ls "Registry::HKCR\CLSID\$clsid"
        Write-Host
      }
    }
  }
}