$appendFile = get-date -Format "yyyy-MM-dd hh:mm:ss"  #this is to append a date and time to the log file
$appendFile = $appendFile.Replace(':', "")

# ------------------------FUNCTION DECLARATION
function write-log {
    Param($Text, [switch]$NoTimeStamp, $appendFile)

    if ($Text -eq "" -or $Text -eq $null) {
        $Text = "No Output"
    }
    if ($NoTimeStamp -eq $false) {
        $Timestamp = "[" + (get-date -Format "yyyy-MM-dd hh:mm:ss") + "] "
        $Text = $Timestamp + $Text
        if (($Text -like "*Error:*") -or ($text -like "*fail*") -or ($text -like "*exception*")) {
            #write-log  -ForegroundColor Red $Text
        }
        else {
            #write-log  -ForegroundColor White $Text 
        }

        #added by daniel
    }
    else {
        $Timestamp = ""
        #write-log -ForegroundColor DarkGray $Text -Separator "`n`t"
    }
    New-Item -Path 'c:\temp' -ItemType Directory -force    
    $LogPath = "c:\temp\Postintall" + $appendFile + ".log"  #   $ThisScriptPath + "\Postintall.log"
   
    
    
    $Text | Out-File $LogPath -Append 
}

#--------------------------------



# --------------------------------------------------------------------
#   Define the variables
# --------------------------------------------------------------------

$ComputerName = "$env:computername"
if ($ComputerName.StartsWith("AC") -or $ComputerName.StartsWith("AS")  ) { 
    $InetPubMOVETODrive = "F"
    $InetPubMOVETODrive2 = "J"
    $firstExtraDisk = "3"
    $secondExtraDisk = "4"
}
else {
    $InetPubMOVETODrive = "D"
    $InetPubMOVETODrive2 = "D"
    $firstExtraDisk = "1"

}

$InetPubRoot = "$($InetPubMOVETODrive):\Inetpub"
$InetpubLogs = "$($InetPubMOVETODrive2):\logs\logfiles"
$InetPubOldLocation = "C:\inetpub"
$InstallFiles = Split-Path $MyInvocation.MyCommand.Path # Get current script location
if (!$InstallFiles)
{
    $InstallFiles=(Get-Location).Path 
}


$Rule1 = "Remove_SRV_ResponseHeader"

# --------------------------------------------------------------------
#   IaaS IIS VM - Initialize Disks before starting
# --------------------------------------------------------------------

try {

   
    Initialize-Disk -Number  $firstExtraDisk -PartitionStyle MBR -PassThru | New-Partition -DriveLetter $InetPubMOVETODrive -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data" -Confirm:$false | Out-Null

    write-log -text "Disk  $InetPubMOVETODrive initialized" -appendFile $appendFile | out-null


    if ($InetPubMOVETODrive2 -eq "J") { 
        Initialize-Disk -Number $secondExtraDisk -PartitionStyle MBR -PassThru | New-Partition -DriveLetter $InetPubMOVETODrive2 -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Logs" -Confirm:$false | Out-Null

        write-log -text "Disk  $InetPubMOVETODrive2 initialized" -appendFile $appendFile | out-null

    }


}
catch { 

    write-log -text "There where an error Initializing Disks. Disk are missing or already initialized" -appendFile $appendFile | out-null
}

# --------------------------------------------------------------------
#   Initialize Log
# --------------------------------------------------------------------

if ( -not (Test-Path "$($InetPubMOVETODrive2):\Install_IIS\Logs" -PathType Container) ) { 

    new-item -itemtype "directory" -path "$($InetPubMOVETODrive2):\Install_IIS" -name "Logs" -Force -ErrorAction SilentlyContinue | Out-Null 
    write-log -text "Directory $($InetPubMOVETODrive2):\Install_IIS created for logs" -appendFile $appendFile | out-null
    
}


#Start-Transcript -IncludeInvocationHeader -path $LogFileName

	
# --------------------------------------------------------------------
# Loading Feature Installation Modules
# --------------------------------------------------------------------

Write-Log "Importing Module ServerManager" -appendFile $appendFile | out-null

Import-Module ServerManager | Out-Null


# --------------------------------------------------------------------
# Installing IIS
# --------------------------------------------------------------------

Write-Log "Installing IIS" -appendFile $appendFile | out-null

#Add-WindowsFeature -Name Web-webserver,Web-mgmt-console,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Static-Content,Web-Http-Redirect,Web-Http-Logging,Web-Log-Libraries,Web-Request-Monitor,Web-HTTP-Tracing,Web-Stat-Compression,Web-Filtering,Web-IP-Security,Web-Windows-Auth,Web-Net-Ext45,Web-AppInit,Web-ASP,Web-Asp-Net45,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Mgmt-Compat,Web-Metabase,Web-Lgcy-Scripting,Web-WMI,Web-Scripting-Tools,Web-Mgmt-Service,NET-Framework-45-ASPNET | Out-Null

# removed: Web-Mgmt-Compat Web-Metabase Web-Lgcy-Scripting Web-WMI added Add Web-Dyn-Compression
Add-WindowsFeature -Name Web-webserver, Web-mgmt-console, Web-Default-Doc, Web-Dir-Browsing, Web-Http-Errors, Web-Static-Content, Web-Http-Redirect, Web-Http-Logging, Web-Log-Libraries, Web-Request-Monitor, Web-HTTP-Tracing, Web-Stat-Compression, Web-Filtering, Web-IP-Security, Web-Windows-Auth, Web-Net-Ext45, Web-AppInit, Web-ASP, Web-Asp-Net45, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Dyn-Compression, Web-Scripting-Tools, Web-Mgmt-Service, NET-Framework-45-ASPNET | Out-Null

write-log -text "Windows features added: Web-webserver, Web-mgmt-console, Web-Default-Doc, Web-Dir-Browsing, Web-Http-Errors, Web-Static-Content, Web-Http-Redirect, Web-Http-Logging, Web-Log-Libraries, Web-Request-Monitor, Web-HTTP-Tracing, Web-Stat-Compression, Web-Filtering, Web-IP-Security, Web-Windows-Auth, Web-Net-Ext45, Web-AppInit, Web-ASP, Web-Asp-Net45, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Dyn-Compression, Web-Scripting-Tools, Web-Mgmt-Service, NET-Framework-45-ASPNET" -appendFile $appendFile | out-null

# --------------------------------------------------------------------
# Loading IIS Modules
# --------------------------------------------------------------------

Write-Log "Importing Module WebAdministration" -appendFile $appendFile | out-null

Import-Module WebAdministration | Out-Null

# --------------------------------------------------------------------
#            Copying old WWW Root data to new folder
# --------------------------------------------------------------------

Write-Log "Moving WWW Root dat to new folder" -appendFile $appendFile | out-null

xcopy $InetPubOldLocation $InetPubRoot /E /O /I /Y /Q | Out-Null
New-Item -Path "$InetpubLogs" -type directory -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "$InetpubLogs\FailedReqLogFiles" -type directory -Force -ErrorAction SilentlyContinue | Out-Null
reg.exe add "HKLM\System\CurrentControlSet\Services\WAS\Parameters" /v ConfigIsolationPath /t REG_SZ /d "$InetPubRoot\temp\appPools" /f | Out-Null

write-log -text "Moved WWW Root data to new folder $InetPubRoot" -appendFile $appendFile | out-null

# --------------------------------------------------------------------
#            Setting IIS Variables
# --------------------------------------------------------------------

Write-Log "Adding and Removing HTTP Reponse Headers" -appendFile $appendFile | out-null

$HeadersToAdd = @{
    "X-Frame-Options"           = "SAMEORIGIN"
    "X-XSS-Protection"          = "1; mode=block"
    "X-Content-Type-Options"    = "nosniff"
    "Strict-Transport-Security" = "max-age=31536000; includeSubDomains; preload"
    "Content-Security-Policy"   = "default-src 'self';"
}
 
$HeadersToAdd.GetEnumerator() | % {
    $HeaderName = $_.Name
    $HeaderValue = $_.Value
    if (!(Get-WebConfiguration "/system.webServer/httpProtocol/customHeaders/add[@Name=""$($HeaderName)""]")) {
        Add-WebConfiguration -Filter "/system.webServer/httpProtocol/customHeaders" -Value @{Name = "$($HeaderName)"; Value = "$($HeaderValue)" }
    }
}    
 
$HeadersToRemove = "X-Powered-By"
$HeadersToRemove | % {
    $HeaderName = $_
    if (Get-WebConfiguration "/system.webServer/httpProtocol/customHeaders/add[@Name=""$($HeaderName)""]") {
        Clear-WebConfiguration -Filter "/system.webServer/httpProtocol/customHeaders/add[@Name=""$($HeaderName)""]"
    }    
}

#-------------------------------------------------------------------------
#        IIS Remove the Server Response Header: "Microsoft-IIS"
#-------------------------------------------------------------------------

Write-Log "IIS Remove the Server Response Header Microsoft-IIS.0" -appendFile $appendFile | out-null

Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering" -name "removeServerHeader" -value "True" | Out-Null


# --------------------------------------------------------------------
#       Remove X-aspNet-Version Globally
# --------------------------------------------------------------------

Write-Log "Remove X-aspNet-Version Globally" -appendFile $appendFile | out-null

Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter "system.web/httpRuntime" -name "enableVersionHeader" -value "False" | Out-Null



#--------------------------------------------------------------------
#               Changing Log Location
#--------------------------------------------------------------------

Write-Log "Changing Log Location" -appendFile $appendFile | out-null

Set-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults"  -name logfile.directory -value "$InetpubLogs" | Out-Null
Set-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults"  -name traceFailedRequestsLogging.directory -value "$InetpubLogs\FailedReqLogFiles" | Out-Null
Set-WebConfigurationProperty "/system.applicationHost/log" -name centralBinaryLogFile.directory -value "$InetpubLogs" | Out-Null
Set-WebConfigurationProperty "/system.applicationHost/log"  -name centralW3CLogFile.directory -value "$InetpubLogs" | Out-Null
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\WebManagement\Server" -name "LoggingDirectory" -value "$InetpubLogs\wmsvc" | Out-Null

#--------------------------------------------------------------------
#         Configure request filtering
#--------------------------------------------------------------------

Write-Log "Configure request filtering" -appendFile $appendFile | out-null

set-WebConfiguration -Filter  /system.webServer/security/requestFiltering/verbs  -value (@{verb = "TRACE"; allowed = "false" }, @{verb = "OPTIONS"; allowed = "false" }, @{verb = "PUT"; allowed = "false" }, @{verb = "DELETE"; allowed = "false" }, @{verb = "GET"; allowed = "true" }, @{verb = "POST"; allowed = "true" }) | Out-Null

#--------------------------------------------------------------------
#              Configure ApplicationPools Defaults
#--------------------------------------------------------------------

Write-Log "Configure Application Pools Defaults" -appendFile $appendFile | out-null

Set-WebConfigurationProperty '/system.applicationHost/applicationPools/applicationPoolDefaults/recycling' -Name logEventOnRecycle -value "Time, Requests, Schedule, Memory, IsapiUnhealthy, OnDemand, ConfigChange, PrivateMemory" | Out-Null
Set-WebConfigurationProperty '/system.applicationHost/applicationPools/applicationPoolDefaults/recycling/periodicRestart' -Name privateMemory -value 1500000 | Out-Null
Set-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/logFile' -name logExtFileFlags -value "Date, Time, ClientIP, UserName, ComputerName, ServerIP, Method, UriStem, UriQuery, HttpStatus, Win32Status, BytesSent, BytesRecv, TimeTaken, ServerPort, UserAgent, Cookie, Referer, ProtocolVersion, HttpSubStatus" | Out-Null

# -------------------------------------------------------------------------------------------
#      Move config history location, temporary files, the path for the Default Web Site
#      and the custom error locations
# -------------------------------------------------------------------------------------------

Write-Log "Moving history, temporary and path for default web site" -appendFile $appendFile | out-null

Set-WebConfigurationProperty '/system.applicationHost/configHistory' -Name path -value "$InetPubRoot\history" | Out-Null
Set-WebConfigurationProperty -Filter '/system.webServer/asp/cache' -name diskTemplateCacheDirectory -value "$InetPubRoot\temp\ASP Compiled Templates" | Out-Null

#--------------------------------------------------------------------
#           Move temporary files
#--------------------------------------------------------------------

Write-Log "Moving Temporary Files" -appendFile $appendFile | out-null

#write-host "Changing temp files path"
Set-WebConfigurationProperty '/system.webServer/httpCompression' -Name directory -value "$InetPubRoot\temp\IIS Temporary Compressed Files" | Out-Null
Set-ItemProperty -path "HKLM:\System\CurrentControlSet\Services\WAS\Parameters" -name "ConfigIsolationPath" -value "$InetPubRoot\temp\appPools" | Out-Null

#----------------------------------------------------------------------------------------
#           Move custom error locations#write-host"Changing custom error location path"
#----------------------------------------------------------------------------------------

Write-Log "Move custom Erro locastions" -appendFile $appendFile | out-null

Set-WebConfigurationProperty /system.webServer/httpErrors/* -Name prefixLanguageFilePath -value "$InetPubRoot\custerr" | Out-Null

#-------------------------------------------------------------------------------------------------
#         Make sure Service Pack and Hotfix Installers know where the IIS root directories are
#         The registry keys aren't created if they don't exist.
#--------------------------------------------------------------------------------------------------

Write-Log "Making sure Service Pack and Hostfix Installers know where the IIS root directories are" -appendFile $appendFile | out-null

#write-host "Updating paths in registry for hotfix and service pack installers" -ForegroundColor Yellow
if (Get-ItemProperty -Path "HKLM:\Software\Microsoft\inetstp" -Name "PathWWWRoot" -ErrorAction "SilentlyContinue") {
    Set-ItemProperty -path "HKLM:\Software\Microsoft\inetstp" -name "PathWWWRoot" -value $InetPubRoot\wwwroot | Out-Null
}

#Do the same for x64 directories (only on x64 systems) 
if (Get-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\inetstp" -Name "PathWWWRoot" -ErrorAction "SilentlyContinue") {
    Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\inetstp" -name "PathWWWRoot" -value $InetPubRoot\wwwroot | Out-Null
}

#-----------------------------------------------------------------------------------------------	
#               Changing the Default Website location
#-----------------------------------------------------------------------------------------------

#Write-Log "Changing the Default Website Location"

#Set-ItemProperty 'IIS:\Sites\Default Web Site' -name physicalPath -value "$InetPubRoot\wwwroot" | Out-Null

# --------------------------------------------------------------------
#               Resetting IIS
# --------------------------------------------------------------------

Write-Log "Resetting IIS" -appendFile $appendFile | out-null

$Command = "IISRESET"
Invoke-Expression -Command $Command | Out-Null

#----------------------------------------------------------------------
#               Enable Web remote management
#----------------------------------------------------------------------

Write-Log "Enabling Web remote Management" -appendFile $appendFile | out-null

Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name EnableRemoteManagement -Value 1 | Out-Null
Set-Service -name WMSVC -StartupType Automatic | Out-Null

#--------------------------------------------------------------------
#               Cleanup
#--------------------------------------------------------------------

Write-Log "Cleanup" -appendFile $appendFile | out-null

Remove-Item $InetpubLogs\FailedReqLogFiles -Recurse -Force

#--------------------------------------------------------------------
#          IIS URL-Rewrite Module
#    Apparent bug in the new IIS feature requires the URL-Rewrite module to still be installed
#    Case Opened with MS  Prashant Kumar <prashku@microsoft.com>  REG:117020315271177
#    Headers removed via Set-WebConfigurationProperty  
#--------------------------------------------------------------------

Write-Log "Installing IIS URL rewrite module" -appendFile $appendFile | out-null

$currentValue = (Get-ItemProperty "hklm:Software\Microsoft\InetStp").MajorVersion

if ($currentValue -eq 10) {

    #write-host "Found Windows Server 2016, modifying version"
    $registryPath = "HKLM:\Software\Microsoft\InetStp"
    $Name = "MajorVersion"
    $newvalue = "7"
    New-ItemProperty -Path $registryPath -Name $name -Value $newvalue -PropertyType DWORD -Force | Out-Null 
    #write-host "IIS re-write Module INSTALL" -ForegroundColor Yellow
    (Start-Process "$InstallFiles\rewrite_amd64.msi" -ArgumentList "/passive" -Wait -Passthru).ExitCode | Out-Null
    #write-host "Reverting version value"
    New-ItemProperty -Path $registryPath -Name $name -Value $currentValue -PropertyType DWORD -Force | Out-Null

}
else {

    #write-host "Windows Server 2016 not found, continuing"
    #write-host "IIS re-write Module INSTALL" -ForegroundColor Yellow
    (Start-Process "$InstallFiles\rewrite_amd64.msi" -ArgumentList "/passive" -Wait -Passthru).ExitCode | Out-Null

}

#write-host "Rewrite Rules Getting Applied- Hit any key to continue" -ForegroundColor Yellow
#Pause

#--------------------------------------------------------------------
#         Add Server Global Setting to URLRewrite
#--------------------------------------------------------------------

Write-Log "Add Server Global Setting to URLRewrite" -appendFile $appendFile | out-null

Import-Module WebAdministration 

Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/rewrite/outboundrules" -name "." -value @{name = $Rule1 } | Out-Null
Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST"  -filter "system.webServer/rewrite/outboundRules/rule[@name='$Rule1']/match" -name "serverVariable" -value "RESPONSE_SERVER" | Out-Null
Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST"  -filter "system.webServer/rewrite/outboundRules/rule[@name='$Rule1']/match" -name "pattern" -value ".*" | Out-Null
Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST"  -filter "system.webServer/rewrite/outboundRules/rule[@name='$Rule1']/action" -name "type" -value "Rewrite" | Out-Null

#--------------------------------------------------------------------
#     Initiation QA Validations - This is IaC Automation Section
#--------------------------------------------------------------------

Write-Log "Initiating QA Validation Process" -appendFile $appendFile | out-null

try {
    #write-host "Initiating QA Process`n`n`n"
    [String[]]$CheckName = @()
    [Int[]]$CheckResult = @()
}
catch {
    #write-host "Error: $($_.Exception.Message)"
}
 

#--------------------------------------------------------------------
#     Path Validations
#--------------------------------------------------------------------

Write-Log "Pathes Validation" -appendFile $appendFile | out-null

$PathValidation = $False

try {
    #write-host "Checking PathValidation"
    $CheckName = "PathValidation"
    $CheckResult = (Test-Path -Path "$InetpubLogs")
}
catch {

    #write-host "Error: $($_.Exception.Message)"
} 

#--------------------------------------------------------------------
#   Remove all pre-existing sites and default app pool
#--------------------------------------------------------------------

Get-IISSite | % { Remove-IISSite $_ -Confirm:$false } -ErrorAction SilentlyContinue

#Remove-WebAppPool -Name "DefaultAppPool" -ErrorAction SilentlyContinue

Get-IISAppPool | % { Remove-WebAppPool -Name $_.Name -ErrorAction SilentlyContinue }

Write-Log "Removed default IIs Site and defaults App pools" -appendFile $appendFile | out-null


#--------------------------------------------------------------------
#     QA Validations Result
#--------------------------------------------------------------------

try {
    $File = New-Object -TypeName psobject
    $QAPath = "$InstallFiles\QA.json" #$LogPath + "\QA.json"
    #write-host "Writing QA Results:"
    for ($i = 0; $i -lt $CheckName.Length; $i++) {           
        $Line = $CheckName[$i] + ": " + $CheckResult[$i]
        #write-host $Line
        $File | Add-Member -MemberType NoteProperty -Name $CheckName[$i] -Value $CheckResult[$i]    
    }
    $File | ConvertTo-Json > $QAPath

    $QAFileContent = get-content $QAPath
    Write-Output $QAFileContent
    #remove-item $QAPath -Force

    #write-host "QA Completed`n`n`n"
}
catch {

    #write-host "Error: $($_.Exception.Message)"
}

#--------------------------------------------------------------------
#     Finishing IaC Automation Section
#--------------------------------------------------------------------

start-sleep 5 | Out-Null

#--------------------------------------------------------------------
#       Reboot Server
#--------------------------------------------------------------------

Write-Log "Server will now be rebooted.  Press Enter to Continue. Log back in after reboot to complete the install" -appendFile $appendFile | out-null
#write-host "Server will now be rebooted.  Press Enter to Continue. Log back in after reboot to complete the install" 
#pause

 
#restart-computer $ComputerName -Force | Out-Null
shutdown -r -f -t: 600