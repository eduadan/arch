$filename="VMDeployAPS_DSC.ps1"
$localpath="d:\script\"
New-Item -ItemType directory -Path $localpath

start-Sleep -s 5

$source = "http://10.246.82.85/"+$filename+".txt"
$destination = "$localpath$filename" +".txt"
 
#copy the file to LM
Invoke-WebRequest $source -OutFile $destination -Verbose

#rename thefile
Rename-Item $destination $filename

#set folder permisions

$sharepath = $localpath
$Acl = Get-ACL $SharePath
$AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule("everyone","read","ContainerInherit,Objectinherit","none","Allow")
$Acl.AddAccessRule($AccessRule)
Set-Acl $SharePath $Acl



#run ps1
Invoke-Expression "$localpath$filename"
