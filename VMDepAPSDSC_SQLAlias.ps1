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
