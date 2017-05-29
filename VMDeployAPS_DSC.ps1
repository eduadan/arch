Param(
    [switch]$LocalStart1,
	[switch]$LocalStart2


	
    )		

$AliasName1 = "SharePointDB_Content"
$AliasName2="SharePointDB_Services"
$DBServer = $sqlserver+'\inst1,1367'
$sqlserver="ACUSSMDSPSQ002"
$sqlserverIp="10.246.82.38"
	
if(!$LocalStart1 -and !$LocalStart2)
{

#Copy-Item C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.8\Downloads\0\*.ps1 c:\windows\temp
# -ErrorAction SilentlyContinue

Get-Process | Out-File -filepath C:\Windows\temp\process.txt

#-------------------------------setting RUnOnce

$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
set-itemproperty $RunOnceKey "VMDeployAPS" 'C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.8\Downloads\0\VMDeployAPS.ps1 -LocalStart1'


		####fixed ip

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

				
		write-host "Starting configuration, please do not close this window"
		Start-Sleep -s 10	
		
		
		#--------------------

		Start-Sleep -s 20

		# create new local admin
		# Create new local Admin user for script purposes
		$Computer = [ADSI]"WinNT://$Env:COMPUTERNAME,Computer"

		$LocalAdmin = $Computer.Create("User", "Shapower")
		$LocalAdmin.SetPassword("SPAdministrator!123")
		$LocalAdmin.SetInfo()
		$LocalAdmin.FullName = "New Local Admin by Powershell"
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

		$domain = "cloudapp.eydev.net"
		$password = "Sy9dO6EP3Bd6gV" | ConvertTo-SecureString -asPlainText -Force
		$username = "$domain\A.AzureAD.01"
		$credential = New-Object System.Management.Automation.PSCredential($username,$password)
		Add-Computer -DomainName $domain -OUPath "OU=SharePoint,OU=Servers,OU=MSP01,DC=cloudapp,DC=eydev,DC=net" -Credential $credential 
		#-Restart -Force
		shutdown -r -t: 20


}
else
{
	if ($LocalStart1)
	{

		
		write-host "Starting configuration, please do not close this window"

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
		#Create SQL aliases 
		CreateAlias $AliasName1 $DBServer
		CreateAlias $AliasName2 $DBServer
		
		#----host file entry
		$filename  = "\\"+ $env:ComputerName  + "\C$\Windows\System32\drivers\etc\hosts" 
		$sqlserverIp + "`t`t" + $sqlserver | Out-File -encoding ASCII -append $filename 
		
		#------------ adding it-sharepoint team as local admin
		$GroupObj = [ADSI]"WinNT://$env:ComputerName/Administrators"
		$GroupObj.Add("WinNT://CLOUDAPP.EYDEV.NET/IT-SharePoint-Team") 

		Start-Sleep -s 10

		$GroupObj.Add("WinNT://CLOUDAPP.EYDEV.NET/A.SP2013USDASETUP.1")
		$GroupObj.Add("WinNT://CLOUDAPP.EYDEV.NET/A.SP2013USDAFARM.1")
		#--------------------

		
		
		
		

				
		$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
		Remove-ItemProperty -path $RunOnceKey -name "VMDeployAPS" -ErrorAction SilentlyContinue
				
	}			
			
	
}

