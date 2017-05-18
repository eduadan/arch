
function copyFiles($SourcePath,$DestPath)
{
	
	write-host "Copying from " $SourcePath " to " $DestPath
	Copy-Item -Recurse -Path $SourcePath -destination $DestPath -Force -Verbose
}
	


$sourceFolder="\\10.246.82.38\sp\VMDeployAPSv2.ps1"
$destin="C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.8\Downloads\0\"

	
copyFiles $sourceFolder $destin

C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.8\Downloads\0\VMDeployAPSv2.ps1
	

