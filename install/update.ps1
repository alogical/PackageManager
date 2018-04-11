$pkgconf = ConvertFrom-Json ([String](Get-Content .package-conf.json))
$file    = "$env:USERPROFILE\AppData\Roaming\PackageManager\conf.json"
$config  = Import-Json $file.FullName

$config.Version = $pkgconf.Version
Write-Configuration $config $file.FullName