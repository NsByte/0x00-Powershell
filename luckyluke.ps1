function Check-WritablePaths {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [ValidateSet(1, 2, 3)]
        [int]$v = 0,  # Default verbosity level to 0 (no verbosity)

        [string]$Domain = $null   # Optional domain for SID resolution
    )

    # Get the current user and their groups
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userName = $currentUser.Name
    $groups = $currentUser.Groups

    # Function to check if a user or group has write permissions
    function HasWritePermission($acl, $identityReference) {
        foreach ($ace in $acl.Access) {
            # Check if the ACE applies to the current user or group
            if ($ace.IdentityReference -eq $identityReference) {
                # Check if the ACE allows write permissions
                if ($ace.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) {
                    return $true
                }
            }
        }
        return $false
    }

    # Function to resolve SID if applicable
    function Resolve-SID ($sid) {
        if ($v -ge 3) { Write-Host "[DEBUG] Resolving SID: $sid" -ForegroundColor Cyan }
        try {
            if ($Domain) {
                $resolvedName = Convert-SidToName -SID $sid -Domain $Domain
            } else {
                $resolvedName = Convert-SidToName -SID $sid
            }
            if ($v -ge 3) { Write-Host "[DEBUG] SID resolved to: $resolvedName (Domain: $Domain)" -ForegroundColor Green }
            return $resolvedName
        } catch {
            if ($v -ge 3) { Write-Host "[DEBUG] SID resolution failed for: $sid" -ForegroundColor Red }
            return $null
        }
    }

    # Check if the provided path exists
    if (-Not (Test-Path -Path $Path)) {
        if ($v -ge 2) {
            Write-Host "The path '$Path' does not exist." -ForegroundColor Red
        }
        return
    }

    # Function to check if current user is the owner
    function IsOwner($acl) {
        $owner = $acl.Owner
        # Check if the owner is a SID and not a string like "O:S-1-5-21..."
        if ($owner -match "^S-1-.*") {
            $resolvedOwner = Resolve-SID -sid $owner
        } else {
            # If it's in the form of "O:S-1-5-21...", strip the "O:" part and resolve
            $owner = $owner -replace "^O:", ""
            $resolvedOwner = Resolve-SID -sid $owner
        }

        if ($resolvedOwner -eq $userName) {
            return $true
        }
        return $false
    }

    # Function to recursively check writable items
    function Check-WritableItems {
        param (
            [string]$CurrentPath
        )

        # Try to get child items in the current path
        $items = Get-ChildItem -Path $CurrentPath -ErrorAction SilentlyContinue

        # If no items are returned, it might be due to access issues
        if (-Not $items -and $v -ge 3) {
            Write-Host "Cannot list contents of '$CurrentPath' (access denied)." -ForegroundColor Yellow
            return
        }

        # Process each item
        foreach ($item in $items) {
            try {
                $acl = Get-Acl -Path $item.FullName -ErrorAction Stop

                # Resolve SIDs in ACL for any IdentityReference
                $resolvedACL = $acl.Access | ForEach-Object {
                    if ($_ -and $_.IdentityReference.IsSecurityIdentifier) {
                        $resolvedSid = Resolve-SID $_.IdentityReference.Value
                        if ($resolvedSid) {
                            $_.IdentityReference = $resolvedSid
                        }
                    }
                    $_
                }

                # Check if the current user is the owner
                if (IsOwner $acl) {
                    if ($v -ge 1) {
                        Write-Host "Writable by owner ($userName): $($item.FullName)"
                    } else {
                        Write-Host "$($item.FullName)"
                    }
                }

                # Check if the current user has write permissions
                if (HasWritePermission $acl $userName) {
                    if ($v -ge 1) {
                        Write-Host "Writable by current user ($userName): $($item.FullName)"
                    } else {
                        Write-Host "$($item.FullName)"
                    }
                }

                # Check if any of the user's groups have write permissions
                foreach ($group in $groups) {
                    $groupName = $group.Translate([System.Security.Principal.NTAccount]).Value
                    if (HasWritePermission $acl $groupName) {
                        if ($v -ge 1) {
                            Write-Host "Writable by group (${groupName}): $($item.FullName)"
                        } elseif ($v -eq 0) {
                            Write-Host "$($item.FullName)"
                        }
                    }
                }

                # Check if resolved SIDs (from ACL) have write permissions
                foreach ($access in $resolvedACL) {
                    if ($access.IdentityReference -eq $userName) {
                        if (HasWritePermission $acl $userName) {
                            Write-Host "Writable by resolved SID ($userName): $($item.FullName)"
                        }
                    }
                }
            } catch {
                # Display errors if verbosity level is 2 or higher
                if ($v -ge 2) {
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
