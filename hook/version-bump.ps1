$InvocationPath = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Definition)
Push-Location $InvocationPath

$current = ConvertFrom-Json ([String](Get-Content .package-version.json))

$version = @{
    Date = (Get-Date).ToShortDateString()
    Major = 0
    Minor = 0
    Patch = 0
}

# MAJOR VERSION NUMBER
$read = $true
while ($read) {
    $version.Major = Read-Host -Prompt ("Major [{0}]:" -f $current.Major)
    if ([String]::IsNullOrEmpty($version.Major)) {
        $version.Major = $current.Major
        break
    }

    if ($version.Major -notmatch '^\d+$') {
        Write-Warning "Invalid input. Only integers are alowed."
        continue
    }

    if ($version.Major -lt $current.Major) {
        while ($true) {
            Write-Warning ("Do you want to reduce the Major version from [{0}] to [{1}]?" -f $current.Major, $version.Major)
            $response = Read-Host -Prompt "[Y/N]"
            if ($response.ToLower() -eq 'y'){
                $read = $false
                break
            }
            elseif ($response.ToLower() -eq 'n') {
                break
            }
            else {
                Write-Warning "Invalid input."
            }
        }
    }
    else {
        $read = $false
    }
}

# MINOR VERSION NUMBER
$read = $true
while ($read) {
    $version.Minor = Read-Host -Prompt ("Minor [{0}]:" -f $current.Minor)
    if ([String]::IsNullOrEmpty($version.Minor)) {
        $version.Minor = $current.Minor
        break
    }

    if ($version.Minor -notmatch '^\d+$') {
        Write-Warning "Invalid input. Only integers are alowed."
        continue
    }

    if ($version.Minor -lt $current.Minor) {
        while ($true) {
            Write-Warning ("Do you want to reduce the Minor version from [{0}] to [{1}]?" -f $current.Minor, $version.Minor)
            $response = Read-Host -Prompt "[Y/N]"
            if ($response.ToLower() -eq 'y'){
                $read = $false
                break
            }
            elseif ($response.ToLower() -eq 'n') {
                break
            }
            else {
                Write-Warning "Invalid input."
            }
        }
    }
    else {
        $read = $false
    }
}

# PATCH VERSION NUMBER
$read = $true
while ($read) {
    $version.Patch = Read-Host -Prompt ("Patch [{0}]:" -f $current.Patch)
    if ([String]::IsNullOrEmpty($version.Patch)) {
        $version.Patch = $current.Patch
        break
    }

    if ($version.Patch -notmatch '^\d+$') {
        Write-Warning "Invalid input. Only integers are alowed."
        continue
    }

    if ($version.Patch -lt $current.Patch) {
        while ($true) {
            Write-Warning ("Do you want to reduce the Patch version from [{0}] to [{1}]?" -f $current.Patch, $version.Patch)
            $response = Read-Host -Prompt "[Y/N]"
            if ($response.ToLower() -eq 'y'){
                $read = $false
                break
            }
            elseif ($response.ToLower() -eq 'n') {
                break
            }
            else {
                Write-Warning "Invalid input."
            }
        }
    }
    else {
        $read = $false
    }
}

# TIMESTAMP AND SAVE
ConvertTo-Json $version > .package-version.json

# UPDATE CONF FILE
$configuration = ConvertFrom-Json ([String](Get-Content .package-conf.json))
$configuration.version = ("{0}.{1}.{2}" -f $version.Major, $version.Minor, $version.Patch)
ConvertTo-Json $configuration > .package-conf.json

# UPDATE PACKAGE FILES

Pop-Location