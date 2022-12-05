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


#region New-Error
$Errors = @()
function New-Error($ErrorMessage, $ErrorType) {
    [CmdletBinding(SupportsShouldProcess)]
    $Temp = New-Object PSObject
    $Temp | Add-Member -Type NoteProperty -Name 'type' -Value $ErrorType
    $Temp | Add-Member -Type NoteProperty -Name 'message' -Value $ErrorMessage
    return $Temp
}


$ResultInstances = @()
$ResultDatabases = @()
$ResultServer = @()
try {
    ($SqlServer = $(hostname)) | Out-Null

    # get instances based on services
    $localInstances = @()
    $Win32_Service = Get-CimInstance -ClassName 'Win32_Service'
    [array]$captions = ($Win32_Service | Where-Object{$_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe"}).Caption
    foreach ($caption in $captions) {
	    if ($caption -eq "MSSQLSERVER") {
		    $localInstances += "MSSQLSERVER"
	    } elseif (-not ($caption -eq "Windows Internal Database")) {
		    $temp = $caption | ForEach-Object{$_.split(" ")[-1]} | ForEach-Object{$_.trimStart("(")} | ForEach-Object{$_.trimEnd(")")}
		    $localInstances += $temp
	    }
    }
    # load the SQL SMO assembly
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | Out-Null

    try {
        $ClusterInstances = @(Get-ClusterResource | Where-Object {$_.ResourceType -eq "SQL Server"} | ForEach-Object{(($_ | Get-ClusterParameter VirtualServerName,InstanceName).value) -join '\'})
    }
    catch {
        $ClusterInstances = @()
        #Not a Cluster, just continue
    }
    
    if ($localInstances.count -gt 0) {
	    foreach ($currInstance in $localInstances) {

            if ($ClusterInstances -gt 0 -and $currInstance -eq "MSSQLSERVER" -or $currInstance -eq "Database"){
                $serverName = ($ClusterInstances | Where-Object {$_ -like "*$currInstance"}).split("\")[0]
            }elseif ($ClusterInstances -gt 0){
                $serverName = $ClusterInstances | Where-Object {$_ -like "*$currInstance"}
            }else{
                if ($currInstance -eq "MSSQLSERVER" -or $currInstance -eq "Database") {
                    $serverName = "$SqlServer"
                } else {
                    $serverName = "$($SqlServer)\$($currInstance)"
                }
            }

		    $server = New-Object -typeName Microsoft.SqlServer.Management.Smo.Server -argumentList $serverName

            ###START Collect Instances###
            $tmpAvailabilityReplicas = $server.AvailabilityGroups.AvailabilityReplicas

            if ($server.DatabaseEngineEdition){
                $tmpinstEngineEdition = $server.DatabaseEngineEdition
            }elseif($server.EngineEdition){
                $tmpinstEngineEdition = $server.EngineEdition
            }else{
                $tmpinstEngineEdition = "MissingValue"
            }
            
            $tmpinst = @{}
            $tmpinst.Add("fullversion",                     "$($server.information.VersionString)")
            $tmpinst.Add("edition",                         "$($server.information.Edition)")
            $tmpinst.Add("platform",                        "$($server.information.Platform)")
            $tmpinst.Add("productlevel",                    "$($server.information.ProductLevel)")
            $tmpinst.Add("rootdirectory",                   "$($server.information.RootDirectory)")
            $tmpinst.Add("namedpipesenabled",               "$($server.NamedPipesEnabled)")
            $tmpinst.Add("tcpenabled",                      "$($server.TcpEnabled)")
            $tmpinst.Add("majorversion",                    "$($server.version.Major)")
            $tmpinst.Add("minorversion",                    "$($server.version.Minor)")
            $tmpinst.Add("build",                           "$($server.version.Build)")
            $tmpinst.Add("databaseenginetype",              "$($server.DatabaseEngineType)")
            $tmpinst.Add("databaseengineedition",           "$($tmpinstEngineEdition)")
            $tmpinst.Add("automatedbackuppreference",       "$($server.AvailabilityGroups.AutomatedBackupPreference)")
            $tmpinst.Add("optimizeadhocworkloads",          "$($server.Configuration.OptimizeAdhocWorkloads.ConfigValue)")
            $tmpinst.Add("maxservermemory",                 $server.Configuration.MaxServerMemory.ConfigValue) 
            $tmpinst.Add("costthresholdforparallelism",     $server.Configuration.CostThresholdForParallelism.ConfigValue)
            $tmpinst.Add("maxdegreeofparallelism",          "$($server.Configuration.MaxDegreeOfParallelism.ConfigValue)")
            $tmpinst.Add("defaultbackupcompression",        "$($server.Configuration.DefaultBackupCompression.ConfigValue)")
            $tmpinst.Add("agentxpsenabled",                 "$($server.Configuration.AgentXPsEnabled.ConfigValue)")
            $tmpinst.Add("databasemailenabled",             "$($server.Configuration.DatabaseMailEnabled.ConfigValue)")
            $tmpinst.Add("adhocdistributedqueriesenabled",  "$($server.Configuration.AdHocDistributedQueriesEnabled.ConfigValue)")
            $tmpinst.Add("backupcompressiondefault",        "$(($server.Configuration.Properties | Where-Object {$_.DisplayName -eq "backup compression default"}).ConfigValue)")
            $tmpinst.Add("containeddatabaseauthentication", "$(($server.Configuration.Properties | Where-Object {$_.DisplayName -eq "contained database authentication"}).ConfigValue)")
            $tmpinst.Add("failovermode",                    "$(($tmpAvailabilityReplicas | Where-Object {$_.Name -eq $serverName}).failovermode)")
            $tmpinst.Add("seedingmode",                     "$(($tmpAvailabilityReplicas | Where-Object {$_.Name -eq $serverName}).SeedingMode)")
            $tmpinst.Add("availabilitymode",                "$(($tmpAvailabilityReplicas | Where-Object {$_.Name -eq $serverName}).AvailabilityMode)")
            $tmpinst.Add("instance",                        $currInstance)
            $tmpinst.Add("type",                            "mssql")

            $tmpinst = New-Object -TypeName PSObject -Property $tmpinst
		    $ResultInstances += $tmpinst
            ###END Collect Instances###


            ###START Collect databases###
            $Databases = @($($server.databases))
            foreach($Database in $Databases){

                if ($Database.Size){
                    $databasesize = $Database.Size.ToString().Split(",")[0]
                }else{
                    $databasesize = $Database.Size
                }

                $tmpdb = @{}
                $tmpdb.Add("computername",               $SqlServer)
                $tmpdb.Add("instancename",               $currInstance)
                $tmpdb.Add("name",                       "$($Database.Name)")
                $tmpdb.Add("status",                     "$($Database.Status)")
                $tmpdb.Add("isaccessible",               "$($Database.IsAccessible)")
                $tmpdb.Add("recoverymodel",              "$($Database.RecoveryModel)")
                $tmpdb.Add("logreusewaitstatus",         "$($Database.LogReuseWaitStatus)")
                $tmpdb.Add("sizemb",                     $databasesize)
                $tmpdb.Add("compatibilitylevel",         "$($Database.CompatibilityLevel)")
                $tmpdb.Add("collation",                  "$($Database.Collation)")
                $tmpdb.Add("owner",                      "$($Database.Owner)")
                $tmpdb.Add("lastbackupdate",             "$($Database.LastBackupDate)")
                $tmpdb.Add("lastdifferentialbackupdate", "$($Database.LastDifferentialBackupDate)")
                $tmpdb.Add("lastlogbackupdate",          "$($Database.LastLogBackupDate)")
                $tmpdb.Add("version",                    "$($Database.Version)")
                $tmpdb.Add("queryoptimizerhotfixes",     "$($Database.QueryOptimizerHotfixes)")
                $tmpdb.Add("pageverify",                 "$($Database.PageVerify)")
                $tmpdb.Add("autoshrink",                 "$($Database.AutoShrink)")
                $tmpdb.Add("autoclose",                  "$($Database.AutoClose)")
                $tmpdb.Add("availabilitygroupname",      "$($Database.AvailabilityGroupName)")
                $tmpdb.Add("containmenttype",            "$($Database.ContainmentType)")
                $tmpdb.Add("encryptionenabled",          "$($Database.EncryptionEnabled)")
                $tmpdb.Add("isfulltextenabled",          "$($Database.IsFullTextEnabled)")
                $tmpdb.Add("ismirroringenabled",         "$($Database.IsMirroringEnabled)")
                $tmpdb.Add("primaryfilepath",            "$($Database.PrimaryFilePath)")
                $tmpdb.Add("maxdop",                     $Database.MaxDop)
                $tmpdb.Add("legacycardinalityestimation","$($Database.LegacyCardinalityEstimation)")
                $tmpdb.Add("parametersniffing",          "$($Database.ParameterSniffing)")
                $tmpdb.Add("type",                       "mssql")

                $tmpdb = New-Object -TypeName PSObject -Property $tmpdb
                $ResultDatabases += $tmpdb
                ###END Collect databases###
            }            
	    }

        #### Fetch wmi information ####
        try {
            $Win32_PageFileUsage = Get-CimInstance -ClassName 'Win32_PageFileUsage'
            $Win32_PowerPlan = Get-CimInstance -ClassName 'Win32_PowerPlan' -Namespace root\cimv2\power -Filter "isActive='true'"
            
        } catch {
            $ErrorType = "Function: Fetch wmi information " + $_.Exception.GetType().Name
            $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
            $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
        }

        ###START Collect ServerInformation###

        $tmpser = @{}
        $tmpser.Add("computername",              $SqlServer)
        $tmpser.Add("pagefileallocatedbasesize", $Win32_PageFileUsage.AllocatedBaseSize)
        $tmpser.Add("pagefilepeakusage",         $Win32_PageFileUsage.PeakUsage)
        $tmpser.Add("pagefilecurrentusage",      $Win32_PageFileUsage.CurrentUsage)
        $tmpser.Add("activepowerplan",           "$($Win32_PowerPlan.ElementName)")       
        $tmpser.Add("sqlserverbrowserstarttype", "$((Get-WmiObject -Query "Select StartMode From Win32_Service Where Name='SQLBrowser'").startmode)")
        $tmpser = New-Object -TypeName PSObject -Property $tmpser
        $ResultServer += $tmpser
        ###END Collect ServerInformation###
    }
} catch {
    $ErrorType = "Function: SQL " + $_.Exception.GetType().Name
    $ErrorMessage = $_.Exception.ErrorRecord.Exception.Message
    $Errors += New-Error -ErrorMessage $ErrorMessage -ErrorType $ErrorType
}


#region assemble json object
$SystemInformation = @{
    'database' = $ResultDatabases
    'instance' = $ResultInstances
    'server' = $ResultServer
    'error' = $Errors
}

$SystemInformation = New-Object -TypeName PSObject -Property $SystemInformation |  ConvertTo-Json -Depth 4

$ErrorActionPreference = $OldErrorActionPreference

return $SystemInformation
