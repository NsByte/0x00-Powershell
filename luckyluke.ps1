function Find-WritablePaths {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [ValidateSet(1, 2, 3)]
        [int]$Verbosity = 0  # Default to 0 (no verbosity)
    )

    # Get the current user and their groups
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userName = $currentUser.Name
    $groups = $currentUser.Groups

    # Function to check if a user or group has write permissions
    function HasWritePermission($acl, $identityReference) {
        foreach ($ace in $acl.Access) {
            if ($ace.IdentityReference -eq $identityReference) {
                if ($ace.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) {
                    return $true
                }
            }
        }
        return $false
    }

    # Check if the provided path exists
    if (-Not (Test-Path -Path $Path)) {
        if ($Verbosity -ge 2) {
            Write-Host "The path '$Path' does not exist." -ForegroundColor Red
        }
        return
    }

    # Function to recursively check writable items
    function Check-WritableItems {
        param ([string]$CurrentPath)

        $items = Get-ChildItem -Path $CurrentPath -ErrorAction SilentlyContinue
        if (-Not $items -and $Verbosity -ge 3) {
            Write-Host "Cannot list contents of '$CurrentPath' (access denied)." -ForegroundColor Yellow
            return
        }

        foreach ($item in $items) {
            try {
                $acl = Get-Acl -Path $item.FullName -ErrorAction Stop

                # Check if the current user has write permissions
                if (HasWritePermission $acl $userName) {
                    if ($Verbosity -ge 1) {
                        Write-Host "Writable by current user ($userName): $($item.FullName)"
                    } else {
                        Write-Host "$($item.FullName)"  # Default output: full path only
                    }
                }

                # Check if any of the user's groups have write permissions
                foreach ($group in $groups) {
                    $groupName = $group.Translate([System.Security.Principal.NTAccount]).Value
                    if (HasWritePermission $acl $groupName) {
                        if ($Verbosity -ge 1) {
                            Write-Host "Writable by group (${groupName}): $($item.FullName)"
                        } elseif ($Verbosity -eq 0) {
                            Write-Host "$($item.FullName)"  # Default: full path only
                        }
                    }
                }
            } catch {
                if ($Verbosity -ge 2) {
                    Write-Host "Error accessing '$($item.FullName)': $_" -ForegroundColor Red
                }
                continue
            }

            # Recursively check subdirectories
            if ($item.PSIsContainer) {
                Check-WritableItems -CurrentPath $item.FullName
            }
        }
    }

    # Start checking from the root path
    Check-WritableItems -CurrentPath $Path
}
