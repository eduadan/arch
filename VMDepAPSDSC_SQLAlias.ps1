
Start-Sleep -s 10

#sql alias
$AliasName1 = "SharePointDB_Content"
$AliasName2="SharePointDB_Services"
#for farm install
$sqlserver="ACUSSMDSPSQ002"
$DBServer = $sqlserver+'\inst1,1367'

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
				#New-Item $x64
			}
			 
			#Define SQL Alias 
			$TCPAliasName = ("DBMSSOCN," + $SQLServerName)
			 
			#Create TCP/IP Aliases
			New-ItemProperty -Path $x86 -Name $AliasName1 -PropertyType String -Value $TCPAliasName
			#New-ItemProperty -Path $x64 -Name $AliasName1 -PropertyType String -Value $TCPAliasName
			
		}
		#----------------------------------------
		 
CreateAlias $AliasName1 $DBServer
CreateAlias $AliasName2 $DBServer

Start-Sleep -s 10
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


