<#
    .SYNOPSIS
        This script is designed to run on remote systems to collect and return systeminformation to Nordlo NordScan agents.
        The script is a part of the WinScan plugin for NordScan, designed to run on windows based operative systems.

    .DESCRIPTION
        Used to gather and collect systeminformation from remote hosts, the script is a part of the WinScan plugin for NordScan.
        The script is designed to run on windows based operative systems. The script requires local admnistrator priviliges to run successfully.

    .EXAMPLE
        .\systemscan.ps1
        This call collects information from the current system and resuturns the result as a multi-lined string in json format

    .NOTES
        Designed to be used with the WinScan plugin for NordScan.

    .LINK
        URLs to related sites
        The first link is opened by Get-Help -Online New-Function

    .INPUTS
        None

    .OUTPUTS
        Multi-lined string in json format.
#>

$OldErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
$OldThreadPriority = [System.Threading.Thread]::CurrentThread.Priority
[System.Threading.Thread]::CurrentThread.Priority = 'Lowest'


#### Errors ####
$Errors = @()
function New-Error($ErrorMessage, $ErrorType) {
    [CmdletBinding(SupportsShouldProcess)]
    $Temp = New-Object PSObject
    $Temp | Add-Member -Type NoteProperty -Name 'type' -Value $ErrorType
    $Temp | Add-Member -Type NoteProperty -Name 'message' -Value $ErrorMessage
    return $Temp
}

#### Fetch wmi information ####
try {
    $Win32_Bios = Get-CimInstance -ClassName 'Win32_Bios'
    $Win32_ComputerSystem = Get-CimInstance -ClassName 'Win32_ComputerSystem'
    $Win32_BaseBoard = Get-CimInstance -ClassName 'Win32_BaseBoard'
    $Win32_ComputerSystemProduct = Get-CimInstance -ClassName 'Win32_ComputerSystemProduct'
    $Win32_OperatingSystem = Get-CimInstance -ClassName 'Win32_OperatingSystem'
    $Win32_LogicalDisk = Get-CimInstance -ClassName 'Win32_LogicalDisk' -ErrorAction Stop | Where-Object -FilterScript {
        $_.DriveType -eq 3 # Only return fixed disks
    }
} catch {
    $ErrorType = "Function: Fetch wmi information " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}

#### Bios ####
$Bios = @{}
$BiosVersion = $null
$FirmWareVersion = $null
try {
    $BiosMajor = $Win32_Bios.SystemBiosMajorVersion
    $BiosMinor = $Win32_Bios.SystemBiosMinorVersion
    $FirmWareMajor = $Win32_Bios.EmbeddedControllerMajorVersion
    $FirmWareMinor = $Win32_Bios.EmbeddedControllerMinorVersion

    if (($null -ne $BiosMajor -and "" -ne $BiosMajor) -and ($null -ne $BiosMinor -and "" -ne $BiosMajor)) {
        $BiosVersion = "$($BiosMajor).$($BiosMinor)"
    }

    if (($null -ne $FirmWareMajor -and "" -ne $FirmWareMajor) -and ($null -ne $FirmWareMinor -and "" -ne $FirmWareMinor)) {
        $FirmWareVersion = "$($FirmWareMajor).$($FirmWareMinor)"
    }

    $Bios += @{
        'bios_name' = $Win32_Bios.Name
        'bios_revision' = $BiosVersion
        'firmware_revision' = $FirmWareVersion
        'release_date' = $Win32_Bios.ReleaseDate.ToString('yyyyMMdd')
        'vendor' = $Win32_Bios.Manufacturer
        'version' = $Win32_Bios.Version
    }
} catch {
    $ErrorType = "Function: Bios " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}

#### System ####
$System = @{}
try {
    $System += @{
        'manufacturer' = $Win32_ComputerSystem.Manufacturer
        'product_name' = $Win32_ComputerSystem.Model
        'serial_number' = $Win32_Bios.SerialNumber
        'uuid' = $Win32_ComputerSystemProduct.UUID
    }
} catch {
    $ErrorType = "Function: System " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}

#### Chassis ####
$Chassis = @{}
try {
    if ($Win32_ComputerSystem.PCSystemType -eq 2) {
        $type = "Laptop"
    } else {
        $type = "Desktop"
    }
    $Chassis += @{
        'type' = $type
        'boot-up_state' = $Win32_ComputerSystem.BootupState
        'manufacturer' = $Win32_ComputerSystem.Manufacturer
        'serial_number' = $Win32_Bios.SerialNumber
    }
} catch {
    $ErrorType = "Function: Chassis " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}

#### CPU ####
$Cpu = @{}
try {
    $cpus = Get-CimInstance -ClassName 'Win32_Processor' -Property Name,NumberOfCores
    $cpuList =  $cpus | measure

    $Cpu += @{     
        'cores' = $cpus[0].NumberOfCores
        'count' =  $cpuList.count
        'type' = $cpus[0].Name
    }
} catch {
    $ErrorType = "Function: CPU " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}

#### Disk ####
$Disk = @()
$queryBitlocker = $true
try {
    if ($Win32_OperatingSystem.ProductType -ne 1){
        #Server OS, has to check that the bitlocker optional feature is installed
        if(!(Get-WmiObject -query "select * from win32_optionalfeature where installstate= 1 and name='BitLocker'")){
            $queryBitlocker = $false
        }
    }
    foreach ($DiskInfo in ($Win32_LogicalDisk | Where-Object {$_.Size})) {
        $bitlockerOn = $false
        $deviceID = $DiskInfo.DeviceID

        if($queryBitlocker){
            $CIMVolume = Get-CimInstance -namespace "Root\cimv2\security\MicrosoftVolumeEncryption" -ClassName "Win32_Encryptablevolume" -Filter "DriveLetter = `'$deviceID`'"
            if($CIMVolume){
                if($CIMVolume.ProtectionStatus -eq 1){
                    $bitlockerOn = $true
                }
            }
        }

        $used = $DiskInfo.Size - $DiskInfo.FreeSpace
        $percent = [math]::Round(($used / $DiskInfo.Size) * 100)
        $Disk += @{
            'available' = $DiskInfo.FreeSpace
            'capacity' = "$($percent)%"
            'mounted_on' = $DiskInfo.DeviceID
            'size' = $DiskInfo.Size
            'type' = $DiskInfo.FileSystem
            'used' = $DiskInfo.Size - $DiskInfo.FreeSpace
            'bitlocker_enabled' = $bitlockerOn
        }
    }

} catch {
    $ErrorType = "Function: Disk " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}

#### Source ####
$ThisHost = @{}
try {

    $ThisHost += @{
        'domain' = $env:USERDNSDOMAIN
        'name' = $env:COMPUTERNAME
    }

} catch {
    $ErrorType = "Function: Source " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}

#### Network ####
$Network = @()
try {
    $NetIPConfiguration = Get-NetIPConfiguration
    $AlreadyDone = @()
    foreach ($NetworkAdapter in $NetIPConfiguration.AllIPAddresses) {
        if ($AlreadyDone -contains $NetworkAdapter.InterfaceAlias) {
            continue
        }
        $IPv4 = @()
        $IPv6 = @()
        $IPAddresses = $NetIPConfiguration.AllIPAddresses | Where-Object {$_.InterfaceAlias -eq $NetworkAdapter.InterfaceAlias}
        foreach ($IPAddress in $IPAddresses) {
            switch ($IPAddress.AddressFamily)
            {
                'IPv4' { $IPv4 += $IPAddress.IPAddress }
                'IPv6' { $IPv6 += $IPAddress.IPAddress }
            }
        }
        $MacAddressRaw = (($NetIPConfiguration | Where-Object {$_.InterfaceAlias -eq $NetworkAdapter.InterfaceAlias}).NetAdapter.MacAddress)
        $MacAddress = $MacAddressRaw -replace '-',':'
        $Temp = New-Object PSObject
        $Temp | Add-Member -Type NoteProperty -Name 'ipv4' -Value $IPv4
        $Temp | Add-Member -Type NoteProperty -Name 'ipv6' -Value $IPv6
        $Temp | Add-Member -Type NoteProperty -name 'mac' -Value $MacAddress
        $Temp | Add-Member -Type NoteProperty -name 'name' -Value $IPAddress.InterfaceAlias
        $Network += $Temp
        $AlreadyDone += $NetworkAdapter.InterfaceAlias
    }
}catch [System.Management.Automation.CommandNotFoundException]{
    $Temp = New-Object PSObject
    $Temp | Add-Member -Type NoteProperty -Name 'ipv4' -Value $null
    $Temp | Add-Member -Type NoteProperty -Name 'ipv6' -Value $null
    $Temp | Add-Member -Type NoteProperty -name 'mac' -Value $null
    $Temp | Add-Member -Type NoteProperty -name 'name' -Value "CommandNotFoundException"
    $Network += $Temp
}catch {
    $ErrorType = "Function: Network " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}


#### Base board ####
$BaseBoard = @{}
try {
    $BaseBoard = @{
        'manufacturer' = $Win32_BaseBoard.Manufacturer
        'product_name' = $Win32_BaseBoard.Product
        'serial_number' = $Win32_BaseBoard.SerialNumber
        'version' = $Win32_BaseBoard.Version
    }
} catch {
    $ErrorType = "Function: Base board " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}

#### OS license ####
$OSLicense = @{}
try {
    $wmiOSLicense = Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL" | Where-Object {$_.LicenseStatus -eq 1 -and $_.Description -like 'Windows*'}

    switch ($wmiOSLicense.LicenseStatus) {
        0 { $licenseStatus = "Unlicensed" }
        1 { $licenseStatus = "Licensed" }
        2 { $licenseStatus = "Out-Of-Box Grace Perios" }
        3 { $licenseStatus = "Out-Of-Tolerance Grace Period" }
        4 { $licenseStatus = "Non-Genuine Grace Period" }
    }

    $OSLicense = [PSCustomObject]@{
        'name' = $wmiOSLicense.Name
        'description' = $wmiOSLicense.Description
        'product_key_channel' = $wmiOSLicense.ProductKeyChannel
        'partial_product_key' = $wmiOSLicense.PartialProductKey
        'license_status' = $licenseStatus
    }

} catch {
    $ErrorType = "Function: OS license " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}

#### Ram ####
$Ram = @{}
try {

    $Ram = @{ # Kommandot svarar i KB
        'total' = $Win32_OperatingSystem.TotalVisibleMemorySize * 1KB
        'free' = $Win32_OperatingSystem.FreePhysicalMemory * 1KB
        'used' = ($Win32_OperatingSystem.TotalVisibleMemorySize - $Win32_OperatingSystem.FreePhysicalMemory) * 1KB
        'virtual' = ($Win32_OperatingSystem.TotalVirtualMemorySize - $Win32_OperatingSystem.TotalVisibleMemorySize) * 1KB
    }

} catch {
    $ErrorType = "Function: Ram " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}

#### Software ####
$Software = @()
$Registry_Software = @(
    "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
)
try {
    foreach ($RegPath in $Registry_Software) {
        try {
            $subKeys = Get-ChildItem $RegPath
        } catch {
            $ErrorType = "Function: Software " + $_.Exception.GetType().Name
            $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
            $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
            continue
        }
        foreach ($subKey in $subKeys) {

            try {
                $item = (Get-ItemProperty $subKey.PSPath)
            } catch {
                $ErrorType = "Function: Software " + $_.Exception.GetType().Name
                $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
                $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
                continue
            }
            If ($item.DisplayName) {
                # Look for creation date on a softwares installation folder.
                if (!$item.InstallDate) {
                    if ($item.InstallLocation) {
                        try {
                            if ($item.InstallLocation -match '"*"'){
                                $item.InstallLocation = $item.InstallLocation.Replace('"','')
                            }
                            $date = (Get-ItemProperty $item.InstallLocation).CreationTime
                            $installDate = Get-Date $date -Format "yyyyMMdd"
                        } catch {
                            $ErrorType = "Function: Software " + $_.Exception.GetType().Name
                            $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
                            $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
                            $installDate = $null
                        }
                    }
                    if ($item.InstallSource -and $null -eq $installDate) {
                        try {
                            $date = (Get-ItemProperty $item.InstallSource).CreationTime
                            $installDate = Get-Date $date -Format "yyyyMMdd"
                        } catch {
                            $ErrorType = "Function: Software " + $_.Exception.GetType().Name
                            $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
                            $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
                            $installDate = $null
                        }
                    }
                } else {
                    $installDate = $item.InstallDate
                }

                $temp = New-Object PSObject
                $temp | Add-Member -Type NoteProperty -Name "name" -Value $item.DisplayName
                $temp | Add-Member -Type NoteProperty -Name "vendor" -Value $item.Publisher
                $temp | Add-Member -Type NoteProperty -Name "version" -Value $item.DisplayVersion
                $temp | Add-Member -Type NoteProperty -Name "install_date" -Value $installDate
                $temp | Add-Member -Type NoteProperty -Name "identifying_number" -Value $item.PSChildName
                $Software += $temp
            }
        }

    }
} catch {
    $ErrorType = "Function: Software " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}

#### Users ####
$Users = @()
try {
    try {
        $QueryUsers = Query User
    } catch {
        $QueryUsers = $null
    }

    if ($QueryUsers) {
        $Users += for ($i = 1; $i -lt $QueryUsers.count; $i++){
            [pscustomobject]@{
                'username' = [regex]::Match($QueryUsers[$i],'^(\s|>)(.*?)\s').Groups[2].Value
                'logon_type' = [regex]::Match($QueryUsers[$i],'rdp|console|Disc').value.ToLower()
                'logon_time' = [regex]::Match($QueryUsers[$i],'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}$').value
            }
        }
    }

} catch {
    $ErrorType = "Function: Users " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}

#### OS ####
$OS = @{}
try {

    try {
        $osInstallDate = Get-Date($Win32_OperatingSystem.InstallDate) -Format yyyyMMdd
        $osLastBoot = Get-Date($Win32_OperatingSystem.LastBootUpTime) -Format "yyyy-MM-dd HH:mm:ss"
        $osLastPatch = (Get-CimInstance -ClassName 'Win32_Quickfixengineering' | Where-Object {$_.InstalledOn} | Sort-Object -Property InstalledOn | Select-Object -last 1).InstalledOn
        $osLastPatch = Get-Date($osLastPatch) -Format yyyyMMdd
    } catch {
        $ErrorType = "Function: OS " + $_.Exception.GetType().Name
        $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
        $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
    }

    try {
        $SystemDriveSize = ($Win32_LogicalDisk | Where-Object {$_.DeviceID -eq $Win32_OperatingSystem.SystemDrive}).Size
    } catch {
        $ErrorType = "Function: OS " + $_.Exception.GetType().Name
        $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
        $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
    }

    $LastLogin = $null
    if ($Users) {
        $SortedUsers = $Users | Sort-Object logon_time -Descending
        $LastLogin = $SortedUsers[0].username
    }

    $OS += @{
        'architecture' = $Win32_OperatingSystem.OSArchitecture
        'version_id' = $Win32_OperatingSystem.BuildNumber
        'install_date' = $osInstallDate
        'last_boot' = $osLastBoot
        'last_patch' = $osLastPatch
        'name' = $Win32_OperatingSystem.Caption
        'serial_number' = $Win32_OperatingSystem.SerialNumber
        'system_drive' = $Win32_OperatingSystem.SystemDrive
        'windows_directory' = $Win32_OperatingSystem.WindowsDirectory
        'system_drive_size' = $SystemDriveSize
        'last_login' = $LastLogin
    }

} catch {
    $ErrorType = "Function: OS " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}

#### Firewall ####
$Firewall = @()
try {
    $NetFirewallProfiles =  Get-NetFirewallProfile -PolicyStore ActiveStore
    foreach($NetFirewallProfile in $NetFirewallProfiles){
        $Temp = New-Object PSObject
        $Temp | Add-Member -Type NoteProperty -Name 'name' -Value $NetFirewallProfile.Name
        $Temp | Add-Member -Type NoteProperty -Name 'enabled' -Value $NetFirewallProfile.Enabled
        $Temp | Add-Member -Type NoteProperty -Name 'defaultinboundaction' -Value $NetFirewallProfile.DefaultInboundAction
        $Temp | Add-Member -Type NoteProperty -Name 'defaultoutboundaction' -Value $NetFirewallProfile.DefaultOutboundAction
        $Temp | Add-Member -Type NoteProperty -Name 'logallowed' -Value $NetFirewallProfile.LogAllowed
        $Temp | Add-Member -Type NoteProperty -Name 'logblocked' -Value $NetFirewallProfile.LogBlocked
        $Temp | Add-Member -Type NoteProperty -Name 'allowlocalfirewallrules' -Value $NetFirewallProfile.AllowLocalFirewallRules
        $Firewall += $Temp
    }
}catch [System.Management.Automation.CommandNotFoundException]{
    $Temp = New-Object PSObject
    $Temp | Add-Member -Type NoteProperty -Name 'name' -Value "CommandNotFoundException"
    $Temp | Add-Member -Type NoteProperty -Name 'enabled' -Value $null
    $Temp | Add-Member -Type NoteProperty -Name 'defaultinboundaction' -Value $null
    $Temp | Add-Member -Type NoteProperty -Name 'defaultoutboundaction' -Value $null
    $Temp | Add-Member -Type NoteProperty -Name 'logallowed' -Value $null
    $Temp | Add-Member -Type NoteProperty -Name 'logblocked' -Value $null
    $Temp | Add-Member -Type NoteProperty -Name 'allowlocalfirewallrules' -Value $null
    $Firewall += $Temp
}catch {
    $ErrorType = "Function: Firewall " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}

#### Antivirus ####
$Antivirus = @()

#Check if client as namespace root/SecurityCenter2 is only available on clients
if ($Win32_OperatingSystem.ProductType -eq 1){
    try {
        $AntivirusProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct 
        foreach ($AntivirusProduct in $AntivirusProducts){
            $hx = '0x{0:x}' -f $AntivirusProduct.productState

            $mid = $hx.Substring(3,2)
            if ($mid -match "10|11") {
                $Enabled = $True
            }
            else {
                $Enabled = $False
            }

            $end = $hx.Substring(5)
            if ($end -eq "00") {
                $UpToDate = $True
            }
            else {
                $UpToDate = $False
            }

            $Temp = New-Object PSObject
            $Temp | Add-Member -Type NoteProperty -Name 'displayname' -Value $AntivirusProduct.displayName
            $Temp | Add-Member -Type NoteProperty -Name 'timestamp' -Value $AntivirusProduct.timestamp
            $Temp | Add-Member -Type NoteProperty -Name 'productstate' -Value $AntivirusProduct.productState
            $Temp | Add-Member -Type NoteProperty -Name 'enabled' -Value $Enabled
            $Temp | Add-Member -Type NoteProperty -Name 'uptodate' -Value $UpToDate
            $Antivirus += $Temp
        }
    }
    catch {
        $ErrorType = "Function: Antivirus " + $_.Exception.GetType().Name
        $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
        $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
    }
}

#### Knowledge Base ####
$KnowledgeBase = @()

try {
    #Fetching updates
    $Session = New-Object -ComObject "Microsoft.Update.Session"
    $Searcher = $Session.CreateUpdateSearcher()
    $historyCount = $Searcher.GetTotalHistoryCount()
    $SearchResult = $Searcher.QueryHistory(0, $historyCount)

    $SearchResult | Where-Object {$_.Title -match "KB\d{7}"} | foreach {
        $Temp = @{}
        $Temp.Add("operation",    "$($_.Operation)")
        $Temp.Add("resultcode",   "$($_.ResultCode)")
        $Temp.Add("install_date", "$($_.Date)")
        $Temp.Add("title",        "$($_.Title)")
        $Temp.Add("kb",           "$($Matches[0])")
        $Temp = New-Object -TypeName PSObject -Property $Temp
        $KnowledgeBase += $Temp
    }
}
catch {
    $ErrorType = "Function: KnowledgeBase " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}

# Create the system information object
$SystemInformation = @{
    'bios' = $Bios
    'system' = $System
    'chassis' = $Chassis
    'motherboard' = $BaseBoard
    'cpu' = $Cpu
    'disk' = $Disk
    'source' = $ThisHost
    'network' = $Network
    'os' = $OS
    'os_license' = $OSLicense
    'ram' = $Ram
    'software' = $Software
    'users' = $Users
    'firewall' = $Firewall
    'antivirus' = $Antivirus
    'knowledgebase' = $KnowledgeBase
    'error' = $Errors
}

$SystemInformation = New-Object -TypeName PSObject -Property $SystemInformation |  ConvertTo-Json -Depth 4

$ErrorActionPreference = $OldErrorActionPreference
[System.Threading.Thread]::CurrentThread.Priority = $OldThreadPriority

return $SystemInformation
