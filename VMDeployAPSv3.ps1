Param(
    [switch]$LocalStart1,
	[switch]$LocalStart2
	

	
    )	

function copyFiles($SourcePath,$DestPath)
{
	$date = (Get-Date).ToString("_MMddyyyy")
	#Defining Source and Destination path
	#$DestPath =  "\\$_\d$\"
	#$SourcePath = "d:\SP"
	#Creating new folder for storing backup
	#New-Item -Path $DestPath -ItemType directory
	#Copying folder
	write-host "Copying from " $SourcePath " to " $DestPath
	Copy-Item -Recurse -Path $SourcePath -destination $DestPath -Force -Verbose
}
	
	

#comon variables
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$scriptName="VMDeployAPSv3.ps1"

$sqlserver="ACUSSMDSPSQ002"
$sqlserverIp="10.246.82.38"

#for lang pack
$langPackSourceFolder="\\"+$sqlserverIp+"\sp\2016\LanguagePacks"
$langPackFolder="d:\sp\LanguagePacks"

#sql alias
$FARMID="AZ44"
$AliasName1 = "SharePointDB_Content"
$AliasName2="SharePointDB_Services"

#for farm install
$DBServer = $sqlserver+'\inst1,1367'
$ConfigDB = $FARMID+'_Config'
$CentralAdminContentDB = $FARMID+'_AdminContent'
$CentralAdminPort = '8898'
$PassPhrase = 'Www.palermo.com2'
$FarmAcc = 'cloudappdev\A.SP2013USDAFARM.1'
$FarmPassword = 'Www.palermo.com3'

#--WebFrontEnd, Application, DistributedCache, Search, Custom, SingleServerFarm
$ServerRole = "WebFrontEndWithDistributedCache"
#"Custom","WebFrontEnd","Application","DistributedCache","SingleServerFarm","Search","ApplicationWithSearch","WebFrontEndWithDistributedCache")]
 


#------------------------------------------------------------		

if(!$LocalStart1 -and !$LocalStart2)
{

#Copy-Item C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.8\Downloads\0\*.ps1 c:\windows\temp
# -ErrorAction SilentlyContinue

#Get-Process | Out-File -filepath C:\Windows\temp\process.txt

#-------------------------------setting RUnOnce

set-itemproperty $RunOnceKey "installSPBorrar" 'C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.8\Downloads\0\VMDeployAPSv3.ps1 -LocalStart1'




		#--------------------

		write-host "Creating new local Admin SHAPOWER user for script purposes"
		Start-Sleep -s 20
		
		# create new local admin
		# Create new local Admin user for script purposes
		$Computer = [ADSI]"WinNT://$Env:COMPUTERNAME,Computer"

		$LocalAdmin = $Computer.Create("User", "Shapower")
		$LocalAdmin.SetPassword("SPAdministrator!123")
		$LocalAdmin.SetInfo()
		$LocalAdmin.FullName = "SHAPOWER"
		$LocalAdmin.SetInfo()
		$LocalAdmin.UserFlags = 64 + 65536 # ADS_UF_PASSWD_CANT_CHANGE + ADS_UF_DONT_EXPIRE_PASSWD
		$LocalAdmin.SetInfo()

		Start-Sleep -s 10

		$GroupObj = [ADSI]"WinNT://$env:ComputerName/Administrators"
		$GroupObj.Add("WinNT://$env:ComputerName/Shapower") 
		
		Start-Sleep -s 10
#---------------------------------
	#-------------
		#joinn domain
		#-----------
		write-host "Joining Domain"
		
		$domain = "cloudapp.eydev.net"
		$password = "Sy9dO6EP3Bd6gV" | ConvertTo-SecureString -asPlainText -Force
		$username = "$domain\A.AzureAD.01"
		$credential = New-Object System.Management.Automation.PSCredential($username,$password)
		Add-Computer -DomainName $domain -OUPath "OU=SharePoint,OU=Servers,OU=MSP01,DC=cloudapp,DC=eydev,DC=net" -Credential $credential 
		#-Restart -Force
		Start-Sleep -s 10
		
		####fixed ip
		
		write-host "setting fixed Ip address"
		
		$IPType = "IPv4"

		try {
			$adapter = Get-NetAdapter | ? {$_.Status -eq "up"}
			$interface = $adapter | Get-NetIPInterface -AddressFamily $IPType
			$IP = ($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress
			$MaskBits = (Get-NetIPAddress $IP).PrefixLength
			$Gateway = ($adapter | Get-NetIPConfiguration).Ipv4DefaultGateway.NextHop
			$DNS = ($adapter | Get-NetIPConfiguration).DNSServer.ServerAddresses
			
			If ($interface.Dhcp -eq "Enabled") {
				
				$interface | Set-NetIPInterface -DHCP Disabled
				
				If (($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
					$adapter | Remove-NetIPAddress -AddressFamily $IPType -Confirm:$false
				}
				
				If (($adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
					$adapter | Remove-NetRoute -AddressFamily $IPType -Confirm:$false
				}
				
				$adapter | New-NetIPAddress -AddressFamily $IPType -IPAddress $IP -PrefixLength $MaskBits -DefaultGateway $Gateway
				$adapter | Set-DnsClientServerAddress -ServerAddresses $DNS
				
			}

		} catch {

			Else {
				Write-Host "DHCP Disabled" -ForegroundColor Yellow
			}
		}		
		
		Restart-computer -force	


}
else
{
	if ($LocalStart1)
	{

		
		write-host "Starting configuration, please do not close this window"
			
		
		Start-Sleep -s 10
		
		#------------ adding it-sharepoint team as local admin
		$GroupObj = [ADSI]"WinNT://$env:ComputerName/Administrators"
		$GroupObj.Add("WinNT://CLOUDAPP.EYDEV.NET/IT-SharePoint-Team") 

		Start-Sleep -s 10

		$GroupObj.Add("WinNT://CLOUDAPP.EYDEV.NET/A.SP2013USDASETUP.1")
		$GroupObj.Add("WinNT://CLOUDAPP.EYDEV.NET/A.SP2013USDAFARM.1")
		#--------------------
				
			write-host "copying lang. packs. DO NOT CLOSE THIS WINDOW"
			#-------language copy
			copyFiles $langPackSourceFolder $langPackFolder
					
			

		#-------------------
		Start-Sleep -s 10
		
		Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy -Value ByPass
		Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System EnableLUA -Value 0 # Temporarily disable UAC
		Set-Service -Name "NetTcpPortSharing" -StartupType Automatic
		
		write-host "Installing lang. packs"
		#lang packs
		Get-ChildItem -path "$langPackFolder" -recurse | ?{$_.Name -eq "setup.exe"} |%{Write-Host "Installing at" $_.FullName; Start-Process -filepath $_.FullName -ArgumentList "/config .\files\setupsilent\config.xml" -wait}
		
		
		set-itemproperty $RunOnceKey "installSPBorrar" 'C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.8\Downloads\0\VMDeployAPSv3.ps1 -LocalStart2'

		
		Start-Sleep -s 10
		
			Restart-computer -force		
				
	}	
	
	if ($LocalStart2)
	{
		Start-Sleep -s 10
		
		
		Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy -Value ByPass
		Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System EnableLUA -Value 0 # Temporarily disable UAC
		Set-Service -Name "NetTcpPortSharing" -StartupType Automatic
		
		
		New-Item -Path "HKCU:\Software\Microsoft\Windows\Currentversion\Policies\Associations" -ErrorAction SilentlyContinue | Out-null

		$lowRiskFileTypes = $(Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" -Name LowRiskFileTypes -ErrorAction SilentlyContinue).LowRiskFileTypes
		if($lowRiskFileTypes -notmatch ".exe"){
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" -Name LowRiskFileTypes -Value ".exe;$lowRiskFileTypes" -ErrorAction SilentlyContinue -Force | Out-Null
		}

		
		#PSConfig.exe -cmd upgrade -inplace b2b -force -cmd applicationcontent -install -cmd installfeatures
		
		function CreateAlias ($AliasName1,$DBServer1)
		{
			#---------CREATING SQL ALIAS
			write-host "sql alias"
			#Name of your SQL Server Alias
			
			 
			# Actual SQL Server Name
			$SQLServerName = $DBServer1
			 
			#These are the two Registry locations for the SQL Alias 
			$x86 = "HKLM:\Software\Microsoft\MSSQLServer\Client\ConnectTo"
			$x64 = "HKLM:\Software\Wow6432Node\Microsoft\MSSQLServer\Client\ConnectTo"
			 
			#if the ConnectTo key doesn't exists, create it.
			if ((test-path -path $x86) -ne $True)
			{
				New-Item $x86
			}
			 
			if ((test-path -path $x64) -ne $True)
			{
				New-Item $x64
			}
			 
			#Define SQL Alias 
			$TCPAliasName = ("DBMSSOCN," + $SQLServerName)
			 
			#Create TCP/IP Aliases
			New-ItemProperty -Path $x86 -Name $AliasName1 -PropertyType String -Value $TCPAliasName
			New-ItemProperty -Path $x64 -Name $AliasName1 -PropertyType String -Value $TCPAliasName
			
		}
		#----------------------------------------
		 
		CreateAlias $AliasName1 $DBServer
		CreateAlias $AliasName2 $DBServer
		
		#----host file entry
		$filename  = "\\"+ $env:ComputerName  + "\C$\Windows\System32\drivers\etc\hosts" 
		$sqlserverIp + "`t`t" + $sqlserver | Out-File -encoding ASCII -append $filename 
		
		#---------------STARTING PSCONFIG
		Write-Host "YOU ARE READY FOR PSCONFIG"
		Start-Sleep -s 10
		
		$FarmAccPWD = ConvertTo-SecureString $FarmPassword  –AsPlaintext –Force
		$cred_FarmAcc = New-Object System.Management.Automation.PsCredential $FarmAcc,$FarmAccPWD
		$SecPassPhrase = ConvertTo-SecureString $PassPhrase –AsPlaintext –Force
		


		Write-Host " - Enabling SP PowerShell cmdlets..."  
		If ((Get-PsSnapin |?{$_.Name -eq "Microsoft.SharePoint.PowerShell"})-eq $null)  
		{
			Add-PsSnapin Microsoft.SharePoint.PowerShell | Out-Null
		}
		Start-SPAssignment -Global | Out-Null
		
		$spFarm = Get-SPFarm | Where-Object {$_.Name -eq $ConfigDB} -ErrorAction SilentlyContinue
		If ($spFarm -eq $null)
		{
		
			#Write-Progress -Activity "SharePoint Farm Configuration" -Status "Creating SharePoint configuration database" -PercentComplete 20
			Write-host "Creating New DB"
			New-SPConfigurationDatabase –DatabaseName "$ConfigDB" –DatabaseServer "$AliasName1" –AdministrationContentDatabaseName "$CentralAdminContentDB" –Passphrase $SecPassPhrase –FarmCredentials $cred_FarmAcc ##-LocalServerRole $ServerRole
		}
		else
		{
		
			if ($IsDistributedCacheHost)
			{
				Connect-SPConfigurationDatabase -DatabaseServer $AliasName1 -DatabaseName $ConfigDB -PassPhrase $SecPassPhrase ##-LocalServerRole $ServerRole
				
			}
			else
			{
				Connect-SPConfigurationDatabase -DatabaseServer $DBServer -DatabaseName $DBName -PassPhrase $SecurePassPhrase ##-LocalServerRole $ServerRole -SkipRegisterAsDistributedCacheHost
				
			}
			
		}
		
		sleep 30
		Write-Host " - Installing Help Collection..."  
		Install-SPHelpCollection -All

		Write-Host " - Securing Resources..."  
		Initialize-SPResourceSecurity

		Write-Host " - Installing Services..."  
		Install-SPService

		Write-Host " - Installing Features..."  
		$Features = Install-SPFeature –AllExistingFeatures -Force

		If ($spFarm -eq $null)
		{
			Write-Host " - Creating Central Admin..."  
			$NewCentralAdmin = New-SPCentralAdministration -Port $CentralAdminPort -WindowsAuthProvider "NTLM"
			
			Write-Host " - Waiting for Central Admin to provision..." -NoNewline  
			sleep 5  
			Write-Host "Created!"
		}
		

		Write-Host " - Installing Application Content..."  
		Install-SPApplicationContent


		# Start Services if needed
		Write-Host "Checking status SharePoint Timer service"
		$timersvc = Get-Service SPTimerV4
		if ($timersvc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running)
		{
			Write-Host "   SharePoint Timer Service not running... starting the service"
			$timersvc.Start()
		}
	 
		if ($IsDistributedCacheHost)
		{
			Write-Host "Checking status Distributed Cache Service"
			$distributedCacheSvc = Get-Service AppFabricCachingService
			if ($distributedCacheSvc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running)
			{
				Write-Host "   AppFabric Caching Service not running... starting the service"
				$distributedCacheSvc.Start()
			}
		}


		Stop-SPAssignment -Global | Out-Null  
		
		Write-Host "all installed..."  
		
		Remove-ItemProperty -path $RunOnceKey -name "installSPBorrar" -ErrorAction SilentlyContinue
			
			
	
	}
}#else
