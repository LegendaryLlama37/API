#Get resource group name
# get funciton app name
# upload zip

#az functionapp deployment source config-zip -g RESOURCEGROUP -n APPNAME --src ZIPFILEPATH
$vars = get-content "$($Env:System_DefaultWorkingDirectory)\$($Env:RELEASE_PRIMARYARTIFACTSOURCEALIAS)\drop\terraform\terraform.tfvars"
$values = New-Object -TypeName psobject
foreach($var in $vars) {
    $pair = $var -split " = "
    $a = $pair[1].Substring(1,$pair[1].length-2)
    $values | Add-Member -MemberType NoteProperty -Name $pair[0] -Value $a
   }
$resourceGroup = "$($values.project)-$($values.environment)-resource-group"
$appname = "$($values.project)-$($values.environment)-function-app"
$zipPath = "$($Env:System_DefaultWorkingDirectory)\$($Env:RELEASE_PRIMARYARTIFACTSOURCEALIAS)\drop\$($Env:BUILD_BUILDID).zip"

$resourceGroup
$appname
$zipPath

#Publish-AzWebapp -ResourceGroupName "$resourceGroup" -Name "$appname" -ArchivePath "$zipPath" -force
az functionapp deployment source config-zip -g "$resourceGroup" -n "$appname" --src "$zipPath"