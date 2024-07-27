param($extended)
$lines
 
$lines = "------------------------------------------"

function whost($a) {
    Write-Host -ForegroundColor Yellow $lines
    Write-Host -ForegroundColor Yellow " $a" 
    Write-Host -ForegroundColor Yellow $lines
}

# Create a folder on the desktop for storing results
$desktopPath = [Environment]::GetFolderPath("Desktop")
$currentDateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$resultsFolder = Join-Path -Path $desktopPath -ChildPath "Scan_Results/SystemScanResults_$currentDateTime"
New-Item -ItemType Directory -Path $resultsFolder -Force | Out-Null

$Access = Get-Date
Write-Output "[***] You ran this script on $Access [***]"

# Determine OS running on target
$ComputerName = $env:computername
$OS = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName | Select-Object -ExpandProperty caption) -replace "Windows" | ForEach-Object { $_.Trim() }
If ($OS -match "10") { Write-Output "[*] You are running Windows 10" }

function Convert-SidToName {
    param (
        [string]$SID
    )

    $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
    $objUser = $objSID.Translate([System.Security.Principal.NTAccount])

    return $objUser.Value
}

$standard_commands = @{
    'Basic System Information Results' = {
        $systemInfoOutput = Start-Process "systeminfo" -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$resultsFolder\SystemInfo.txt" -ErrorAction SilentlyContinue
        if ($systemInfoOutput.ExitCode -eq 0) {
            Write-Host "System information saved to: $resultsFolder\SystemInfo.txt"
        } else {
            Write-Host "Failed to retrieve system information."
        }
    };
    'Environment Variables Results' = { 
        Get-ChildItem Env: | ft Key,Value | Out-File "$resultsFolder\EnvironmentVariables.txt" -Encoding utf8 
    };
    'Network Information Results'                         = { 
        Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address | Out-File "$resultsFolder\NetworkInfo.txt" -Encoding utf8 
    };
    'DNS Servers Results'                                 = { 
        Get-DnsClientServerAddress -AddressFamily IPv4 | ft | Out-File "$resultsFolder\DNSServers.txt" -Encoding utf8 
    };
    'ARP cache Results'                                   = { 
        Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State | Out-File "$resultsFolder\ARPCache.txt" -Encoding utf8 
    };
    'Routing Table Results'                               = { 
        Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex | Out-File "$resultsFolder\RoutingTable.txt" -Encoding utf8 
    };
    'Network Connections Results' = {
        $netstatOutput = Start-Process "netstat" -ArgumentList "-ano" -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$resultsFolder\NetworkConnections.txt" -ErrorAction SilentlyContinue
        if ($netstatOutput.ExitCode -eq 0) {
            Write-Host "Network connections information saved to: $resultsFolder\NetworkConnections.txt"
        } else {
            Write-Host "Failed to retrieve network connections information."
        }
    };
    'Connected Drives Results'                            = { 
        Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"} | ft | Out-File "$resultsFolder\ConnectedDrives.txt" -Encoding utf8 
    };
    'Firewall Config Results' = {
        $firewallConfigOutput = Start-Process "netsh" -ArgumentList "advfirewall firewall show rule all" -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$resultsFolder\FirewallConfig.txt" -ErrorAction SilentlyContinue
        if ($firewallConfigOutput.ExitCode -eq 0) {
            Write-Host "Firewall configuration information saved to: $resultsFolder\FirewallConfig.txt"
        } else {
            Write-Host "Failed to retrieve firewall configuration information."
        }
    };
    'Credential Manager Results' = {
        $credentialManagerOutput = Start-Process "cmdkey" -ArgumentList "/list" -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$resultsFolder\CredentialManager.txt" -ErrorAction SilentlyContinue | Out-Null
        if ($credentialManagerOutput.ExitCode -eq 0) {
            Write-Host "Credential Manager information saved to: $resultsFolder\CredentialManager.txt"
        } else {
            Write-Host "Failed to retrieve Credential Manager information."
        }
    };


    'Auto Logon Registry Settings for All Users' = {
        param ($resultsFolder)

        try {
            $allUsersRegistryPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            $regKey = Get-Item -Path $allUsersRegistryPath

            if ($regKey) {
                $autoLogonSID = $regKey.GetValue('AutoLogonSID')
                $lastUsedUsername = Convert-SidToName -SID $autoLogonSID
                $autoLogonSettings = New-Object PSObject -Property @{
                    'AutoLogonSID'      = $autoLogonSID
                    'LastUsedUsername'  = $lastUsedUsername
                    'Shell'             = $regKey.GetValue('Shell')
                    'Userinit'          = $regKey.GetValue('Userinit')
                }

                Write-Output "Auto Logon Registry Settings for All Users"
                $autoLogonSettings | Format-Table | Out-File "$resultsFolder\AutoLogonSettings.txt" -Encoding utf8
            } else {
                Write-Output "Failed to open registry key: $allUsersRegistryPath"
            }
        } catch {
            Write-Output "Error accessing registry: $_"
        }
    };


    'Local Groups Results'                                = { 
        Get-LocalGroup | ft Name | Out-File "$resultsFolder\LocalGroups.txt" -Encoding utf8 
    };
    'Local Administrators Results'                        = { 
        Get-LocalGroupMember Administrators | ft Name, PrincipalSource | Out-File "$resultsFolder\LocalAdministrators.txt" -Encoding utf8 
    };
    'User Directories Results'                            = { 
        Get-ChildItem C:\Users | ft Name | Out-File "$resultsFolder\UserDirectories.txt" -Encoding utf8 
    };
    'Searching for SAM backup files Results'              = { 
        Test-Path %SYSTEMROOT%\repair\SAM ; Test-Path %SYSTEMROOT%\system32\config\regback\SAM | Out-File "$resultsFolder\SAMBackupFiles.txt" -Encoding utf8 
    };
    'Installed Software Directories Results'              = { 
        Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" | ft Parent,Name,LastWriteTime | Out-File "$resultsFolder\InstalledSoftwareDirectories.txt" -Encoding utf8 
    };
    'Software in Registry Results'                        = { 
        Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name | Out-File "$resultsFolder\SoftwareInRegistry.txt" -Encoding utf8 
    };
    'Folders with Everyone Permissions Results'           = { 
        Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | ForEach-Object { try { Get-Acl $_ -ErrorAction Stop | Where-Object {($_.Access | select -ExpandProperty IdentityReference) -match "Everyone"} } catch {} } | ft | Out-File "$resultsFolder\FoldersWithEveryonePermissions.txt" -Encoding utf8 
    };
    'Folders with BUILTIN\User Permissions Results' = {
        try {
            $foldersWithPermissions = Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" -ErrorAction Stop | ForEach-Object {
                try {
                    $acl = Get-Acl $_ -ErrorAction Stop
                    $acl | Where-Object { $_.Access.IdentityReference -match "BUILTIN\\Users" } | Format-List Path, AccessToString
                } catch {
                    Write-Host "Error occurred while retrieving permissions for $($_.FullName): $_" -ForegroundColor Yellow
                }
            }
            $foldersWithPermissions | Out-File "$resultsFolder\FoldersWithBuiltinUsersPermissions.txt" -Encoding utf8
            Write-Host "Folders with BUILTIN\User permissions information saved to: $resultsFolder\FoldersWithBuiltinUsersPermissions.txt"
        } catch {
            Write-Host "Failed to retrieve folders with BUILTIN\User permissions: $_" -ForegroundColor Red
        }
    };
    'Checking registry for AlwaysInstallElevated Results' = { 
        Test-Path -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer" | Out-File "$resultsFolder\AlwaysInstallElevatedResults.txt" -Encoding utf8 
    };
    'Unquoted Service Paths Results'                      = { 
        Get-WmiObject -Class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where-Object {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName, DisplayName, Name | ft | Out-File "$resultsFolder\UnquotedServicePaths.txt" -Encoding utf8 
    };
    'Scheduled Tasks Results' = { 
        Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State | Out-File "$resultsFolder\ScheduledTasks.txt" -Encoding utf8 
    };
    'Tasks Results' = {
        $tasksLocations = @(
            "C:\Windows\System32\Tasks",  # System-wide tasks
            "C:\Windows\Tasks"            # Legacy tasks location
        )

        # Add user-specific task folders
        $userSIDs = Get-ChildItem "C:\Users" | Where-Object { $_.PSIsContainer } | ForEach-Object { $_.Name }
        foreach ($SID in $userSIDs) {
            $tasksLocations += "C:\Windows\System32\Tasks\$SID"
        }

        $allTasks = @()
        foreach ($location in $tasksLocations) {
            $tasks = Get-ChildItem $location -Recurse -File -ErrorAction SilentlyContinue
            if ($tasks) {
                foreach ($task in $tasks) {
                    $taskContent = Get-Content $task.FullName -Raw
                    $taskInfo = [PSCustomObject]@{
                        Location = $location
                        Name = $task.Name
                        LastWriteTime = $task.LastWriteTime
                        Content = $taskContent
                    }
                    $allTasks += $taskInfo
                }
            }
        }

        if ($allTasks) {
            $allTasks | Export-Csv -Path "$resultsFolder\AllTasks.csv" -NoTypeInformation
            Write-Host "Tasks information saved to: $resultsFolder\AllTasks.csv"
        } else {
            Write-Host "No tasks found."
        }
    };
    'Startup Commands Results'                            = { 
        Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | ft | Out-File "$resultsFolder\StartupCommands.txt" -Encoding utf8 
    };
    'Host File content Results'                           = { 
        Get-Content $env:windir\System32\drivers\etc\hosts | Out-File "$resultsFolder\HostFileContent.txt" -Encoding utf8 
    };
    'Running Services Results'                            = { 
        Get-Service | Select Name,DisplayName,Status | Sort-Object Status | Format-Table -AutoSize | Out-File "$resultsFolder\RunningServices.txt" -Encoding utf8 
    };
    'Installed Softwares in Computer Results'             = { 
        Get-WmiObject -Class win32_product | select Name, Version, Caption | ft -hidetableheaders -autosize | Out-File "$resultsFolder\InstalledSoftwares.txt" -Encoding utf8 
    };
    'Installed Patches Results'                           = { 
        Get-WmiObject -class Win32_QuickFixEngineering -namespace "root\cimv2" | select HotFixID, InstalledOn | ft -autosize | Out-File "$resultsFolder\InstalledPatches.txt" -Encoding utf8 
    };
    'Recent Documents Used Results'                       = { 
        Get-ChildItem "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue | select Name | ft -hidetableheaders | Out-File "$resultsFolder\RecentDocumentsUsed.txt" -Encoding utf8 
    };
    'Potentially Interesting Files Results' = {
        $fileExtensions = @("*.zip","*.rar","*.7z","*.gz","*.conf","*.rdp","*.kdbx","*.crt","*.pem","*.ppk","*.xml","*.ini","*.vbs","*.bat","*.ps1","*.cmd")
        $interestingFiles = Get-ChildItem "C:\Users\" -Recurse -Include $fileExtensions -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
        $interestingFiles | Out-File -FilePath "$resultsFolder\PotentiallyInterestingFiles.txt" -Encoding utf8
        $interestingFiles | Format-Table -AutoSize
    };

    'Last 10 Modified items Results'                      = { 
        Get-ChildItem "C:\Users" -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 10 | ForEach-Object { $_.FullName } | Out-File "$resultsFolder\Last10ModifiedItems.txt" -Encoding utf8 
    };
    'Stored Credentials Results'                          = { 
        cmdkey /list | Out-File "$resultsFolder\StoredCredentials.txt" -Encoding utf8 
    };
    'Localgroup Administrators Results'                   = { 
        net localgroup Administrators | Out-File "$resultsFolder\LocalgroupAdministrators.txt" -Encoding utf8 
    };
    'Current User Results'                                = { 
        Write-Output "$env:UserDomain\$env:UserName" | Out-File "$resultsFolder\CurrentUser.txt" -Encoding utf8 
    };
    'User Privileges Results' = {
        $privileges = Start-Process "whoami" -ArgumentList "/priv" -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$resultsFolder\UserPrivileges.txt" -ErrorAction Stop
        if ($privileges.ExitCode -eq 0) {
            Write-Host "User privileges saved to: $resultsFolder\UserPrivileges.txt"
        } else {
            Write-Host "Failed to retrieve user privileges."
            }
    };

    'Local Users Results'                                 = { 
        Get-LocalUser | ft | Out-File "$resultsFolder\LocalUsers.txt" -Encoding utf8 
    };
    'Logged in Users Results' = { 
        Get-CimInstance Win32_LoggedOnUser | ft | Out-File "$resultsFolder\LoggedInUsers.txt" -Encoding utf8 
    };
    'Running Processes Results'                           = { 
        Get-WmiObject -Query "Select * from Win32_Process" | Where-Object { $_.Name -notlike "svchost*" } | Select-Object Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize | Out-File "$resultsFolder\RunningProcesses.txt" -Encoding utf8 
    }
}

function RunCommands($commands) {
    $totalCommands = $commands.Count
    $progressIndex = 1

    ForEach ($command in $commands.GetEnumerator()) {
        whost $command.Name
        Write-Progress -Activity "Running command: $($command.Name)" -Status "Progress $progressIndex of $totalCommands" -PercentComplete (($progressIndex / $totalCommands) * 100)
        try {
            & $command.Value
        } catch {
            Write-Host "Error occurred while executing $($command.Name): $_"
        }
        $progressIndex++
    }
}

RunCommands($standard_commands)