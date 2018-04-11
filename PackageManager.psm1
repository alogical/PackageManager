<#
.SYNOPSIS
    Basic software package manager.

.DESCRIPTION
    Provides a system for managing software and update distribution using a
    distributed file system.

.NOTES
    Author: Daniel K. Ives
    Email:  daniel.ives@live.com
#>

Add-Type -AssemblyName System.IO.Compression.FileSystem

###############################################################################
###############################################################################
## SECTION 01 ## PUBILC FUNCTIONS AND VARIABLES
##
## Pass-thru Export-ModuleMember calls export all functions and variables
## to the global session that were passed to this modules session from nested
## modules.
###############################################################################
###############################################################################

# Module Configuration Management

function Write-Configuration {
    param(
        # Data structure to be converted to json format and saved to disk.
        [Parameter(
            Mandatory = $true,
            Position = 0)]
            $Data,
        
        # Save path for writing the configuration data to disk.
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [String]
            $Path
    )
    $json = ConvertTo-Json -InputObject $Data -Depth 10
    $json | Out-File $Path -Force
}

function Debug-PackageManager {
    Write-Host "PackageManager Configuration..." -ForegroundColor Magenta
    Write-Host ($Configuration | Get-Member -MemberType NoteProperty | Format-List | Out-String) -ForegroundColor Cyan

    foreach ($entry in $Configuration.Repository.GetEnumerator()) {
        $repository = @{}
        $repository.Configuration = Import-Configuration $entry.Value
        $repository.Index = Import-Index $repository.Configuration.Index

        Write-Host ("{0} Repository Configuration..." -f $entry.Key) -ForegroundColor Magenta

        # Only display the configuration file for the [installed] repository
        if ($entry.Key -eq 'Installed') {
            Write-Host ($repository.Configuration | Get-Member -MemberType NoteProperty | Format-List | Out-String) -ForegroundColor Cyan
            continue
        }
        
        # Validate Repository
        if (Test-Path $repository.Configuration.Local) {
            Write-Host "Local Repository Path Valid: TRUE" -ForegroundColor Green
        }
        else {
            Write-Host "Local Repository Path Valid: FALSE" -ForegroundColor Red
        }

        if (Test-Path $repository.Configuration.Remote) {
            Write-Host "Remote Repository Path Valid: TRUE" -ForegroundColor Green
        }
        else {
            Write-Host "Remote Repository Path Valid: FALSE" -ForegroundColor Red
        }

        if ($repository.Configuration.Version -eq $ModuleVersion) {
            Write-Host "Repository Version Supported: TRUE" -ForegroundColor Green
        }
        else {
            Write-Host "Repository Version Supported: FALSE" -ForegroundColor Red
        }

        if ($repository.Configuration.Revision -eq $repository.Index.Revision) {
            Write-Host "Repository Revision Valid: TRUE" -ForegroundColor Green
        }
        else {
            Write-Host "Repository Revision Valid: TRUE" -ForegroundColor Green
        }

        Write-Host ($repository.Configuration | Get-Member -MemberType NoteProperty | Format-List | Out-String) -ForegroundColor Cyan
    }
}

# Repository Management

function Initialize-Repository {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0)]
        [String]
            $Name,

        [Parameter(
            Mandatory = $false,
            Position = 1)]
        [Alias('FullName', 'Path')]
        [String]
            $LiteralPath = (Get-Location).ProviderPath
    )

    # Create Repository Configuration
    $params = @{
        Name = $Name
        Local = $LiteralPath
    }
    $repository = New-Repository @params

    # Save Configuration
    Write-Configuration $repository $repository.Path

    # Create Repository Index
    $params = @{
        Name = $Name
        Path = $repository.Index
        Revision = $repository.Revision
    }
    $index = New-Index @params

    # Save Index
    Write-Configuration $index $index.Path

    # Link to Local Repository
    if (!(Register-Repository $repository.Path)) {

        # Re-attempt Registration
        if (!(Unregister-Repository $repository.Name -Silent)) {
            return
        }
        Register-Repository $repository.Path | Out-Null
    }
}

function Register-Repository {
    [CmdletBinding()]
    param(
        # Remote repository configuration file path.
        [Parameter(Mandatory = $true)]
        [String]
            $Path
    )

    $remote = Import-Configuration $Path

    if ($Configuration.Repository.ContainsKey($remote.Name)) {
        Write-Error ("Repository [{0}] is already registered." -f $remote.Name)
        return $false
    }

    # Create Local Repository
    $params = @{
        Name = $remote.Name
        Local = (Join-Path $Configuration.AppData.Repository $remote.Name)
        Remote = $remote.Path
    }
    $repository = New-Repository @params

    $params = @{
        Name = $repository.Name
        Path = $repository.Index
    }
    $index = New-Index @params

    # Create the local repository folder
    New-Item (Join-Path $Configuration.AppData.Repository $repository.Name) -ItemType Directory | Out-Null
    Write-Configuration $repository $repository.Path
    Write-Configuration $index $index.Path

    # Register Local Repository
    $Configuration.Repository.Add($repository.Name, $repository.Path)
    Write-Configuration $Configuration $Configuration.Path

    Sync-Repository $repository.Name | Out-Null

    return $true
}

function Unregister-Repository {
    param(
        [Parameter(Mandatory = $true)]
        [String]
            $Repository,

        [Parameter(Mandatory = $false)]
        [Switch]
            $Silent
    )

    if (!$Configuration.Repository.ContainsKey($Repository)) {
        Write-Error "Repository is not registered."
        return $false
    }

    # Remove Orphaned Packages
    $packages = Get-Package -Repository 'Installed' | Where-Object {$_.Repository -eq $Repository}
    if ($packages) {
        if ($Silent) {
            return $false
        }

        Write-Warning ("{0} packages installed from repository [{1}]." -f
            $packages.Count,
            $Repository)

        # Prompt User for Choice
        $options = @('y', 'n', 'c')
        while ($true) {
            $response = Read-Host "Remove packages installed from <$repository> [Y]es, [N]o, [C]ancel: [Y]"

            # Default Option [Enter]
            if ([String]::IsNullOrEmpty($response.Trim())) {
                $response = 'y'
                break
            }

            # Normalize Input
            $response = $response.ToLower().Trim()

            # Verify Input
            if ($options -contains $response) {
                break
            }
            else {
                Write-Warning "Invalid option."
            }
        }

        # Execute Chosen Action
        switch ($response) {
            y {
                foreach ($pkg in $packages) {
                    Uninstall-Package $pkg | Out-Null
                }
            }

            n {
                break
            }

            c {
                return $false
            }
        }
    }

    # Delete Local Repository Files
    Remove-Item -LiteralPath $Configuration.Repository[$Repository] -Recurse

    # Remove Registration from Configuration File
    $Configuration.Repository.Remove($Repository)
    Write-Configuration $Configuration $Configuration.Path

    return $true
}

function Sync-Repository {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [String]
            $Repository
    )

    # Repository (installed) has no remote directory.
    if ($Repository -eq 'Installed') {
        return $false
        
    }

    if ([String]::IsNullOrEmpty($Repository)) {
        foreach ($repo in $Configuration.Repository.GetEnumerator()) {
            Sync-Repository $repo.Key
        }
        return
    }

    if (!$Configuration.Repository.ContainsKey($Repository)) {
        Write-Error "Repository [$Repository] does not exist."
        return $false
    }

    $local = Import-Json $Configuration.Repository[$Repository]

    if ([String]::IsNullOrEmpty($local.Remote)){
        Write-Error "Repository [$Repository] has no remote directory defined."
        return $false
    }

    $remote = Import-Json $local.Remote
    if ($remote.Revision -gt $local.Revision) {
        Copy-Item $remote.Index $local.Index -Force

        $local.Revision = $remote.Revision
        $index = Import-Json $local.Index
        $index.Path = $local.Index

        Write-Configuration $local $local.Path
        Write-Configuration $index $index.Path

        return $true
    }
    return $false
}

function Register-Package {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0)]
        [PSTypeName('PackageInfo')]
        [PSCustomObject]
            $Package,

        # Repository Configuration File Path
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [ValidateScript({Test-Path $_})]
        [String]
            $Repository
    )

    # Serialize Package Object
    #$Data = Serialize-Package $Package

    # Retrieve Repository Index
    try {
        $Config = Import-Configuration $Repository
        $Index = Import-Index $Config.Index
    }
    catch {
        Write-Error "Could not register package with $Repository.  Repository configuration or index files could not be loaded."
        return $false
    }

    # Add Package Information to Repository Index
    if (!$Index.Packages.ContainsKey($Package.Name)) {
        $Index.Packages.Add($Package.Name, $Package)
    }
    else {
        $Index.Packages[$Package.Name] = $Package
    }

    $Index.Revision++
    $Config.Revision++

    # Save Index
    Write-Configuration -Data $Index -Path $Index.Path
    Write-Configuration -Data $Config -Path $Config.Path

    return $true
}

function Unregister-Package {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0)]
        [String]
            $Package,

        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [String]
            $Repository
    )

    if (!$Configuration.Repository.ContainsKey($Repository)) {
        Write-Error "$Repository could not be found."
        return $false
    }

    $config = Import-Configuration $Configuration.Repository[$Repository]
    $index = Import-Index $config.Index
    try {
        $index.Packages.Remove($Package)
        $json = ConvertTo-Json $index
        $json | Out-File $config.Index -Force
    }
    catch {
        return $false
    }
    
    return $true
}

# Package Management

function Install-Package {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = 'Object',
            ValueFromPipeline = $true)]
        [PSTypeName('PackageInfo')]
        [PSCustomObject]
            $InputObject,

        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = 'String',
            ValueFromPipelineByPropertyName = $true)]
        [Alias('Name')]
        [String]
            $Package,

        [Parameter(
            Mandatory = $false,
            Position = 1,
            ParameterSetName = 'String',
            ValueFromPipelineByPropertyName = $true)]
        [String]
            $Repository,

        [Parameter(Mandatory = $false)]
        [Switch]
            $Update
    )

    # Boolean Indicator of Success/Failure
    $ExitStatus = $true

    # Process Arguments
    if ($PSCmdlet.ParameterSetName -eq 'Object') {
        $Package = $InputObject.Name
        $Repository = $InputObject.Source
        $pkg = $InputObject
    }
    # Locate Package Manifest
    else {
        if ([String]::IsNullOrEmpty($Repository)) {
            $pkg = Find-Package $Package -Remote
        }
        else {
            $pkg = Get-Package $Package $Repository
        }

        if ($pkg -eq $null) {
            Write-Error "$Package could not be found."
            return $false
        }
    }

    # Load default installation registry repository
    $installed = @{}
    $installed.Config = Import-Configuration $Configuration.Repository['Installed']
    $installed.Index  = Import-Index $installed.Config.Index
    
    # Verify Package Not Already Installed
    if (!$Update -and $installed.Index.Packages.Containskey($Package)) {
        Write-Error "$Package is already installed."
        return $false
    }

    # Create Temporary Directory
    $temp = Join-Path $Configuration.AppData.Temp $pkg.SHA1
    New-Item $temp -ItemType Directory | Out-Null

    Push-Location $Configuration.AppData.Temp

    # Extract Package Content
    if (Extract-Package $pkg $temp) {

        # Move Current Location to Extraction Directory
        Push-Location $temp

        # NOTE:
        # Opportunity for package writer to perform any package specific installation actions
        #
        # Invoking the custom update|install expressions supplied by the package is the package
        # writers opportunity to perform any configuration and installation tasks that are unique
        # to the package (e.g. creating shortcuts, initializing appdata folders, creating or
        # merging configuration files, etc...).
        
        # IMPORTANT:
        # After executing, the update|install scripts called here should return extended information
        # about any directories, files, and registry entries created to be incorporated into the
        # files manifest that accompanies the package info registered in the installed repository.
        #
        # This information is important for when removing the package files during un-installaion.
        # The extended information will be passed as arguments to the package's uninstall expression.

        # Invoke-Installation | Filter Output to only custom object data
        $ExtendedInfo = $null
        if ($Update) {
            try {
                if (![String]::IsNullOrEmpty($pkg.Update)) {
                    $ExtendedInfo = Invoke-Expression $pkg.Update | Where-Object {$_ -is [PSCustomObject]}
                }
            }
            catch {
                $ExitStatus = $false
            }
        }
        else {
            try {
                if (![String]::IsNullOrEmpty($pkg.Install)) {
                    $ExtendedInfo = Invoke-Expression $pkg.Install | Where-Object {$_ -is [PSCustomObject]}
                }
            }
            catch {
                $ExitStatus = $false
            }
        }

        # Attempt Installation
        if ($ExitStatus) {
            $ExitStatus = Auto-Install -Package $pkg -Path $temp -Extended $ExtendedInfo
        }
        else {
            # Package Installation Script Failed... Attempt Recovery
        }

        Pop-Location
    }
    else {
        Write-Error "Package extraction failed! Cancelling installation."
        $ExitStatus = $false
    }

    # Cleanup Temporary Directory
    Remove-Item $temp -Recurse

    return $ExitStatus
}

function Uninstall-Package {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]
            $Package,

        [Parameter(Mandatory = $true)]
        [Switch]
            $Clean
    )
    $pkg = Get-Package $Package 'Installed'

    # Invoke Uninstall Logic
    if (![String]::IsNullOrEmpty($pkg.Uninstall)) {
        Invoke-Expression $pkg.Uninstall
    }
    else {
        # Start-Uninstall
        Auto-Uninstall $pkg
    }

    # Load checkpoint registry index
    $Index = Import-Checkpoint (Join-Path $Configuration.AppData.Checkpoint index.json)
    $checkpoints = $Index[$Package]

    # Remove package checkpoints
    foreach ($chk in $checkpoints.ToArray()) {
        Remove-Item $chk.Archive
        $checkpoints.Remove($chk)
    }

    # Unregister package from checkpoint registry
    $Index.Remove($Package)

    Write-Configuration $Index (Join-Path $Configuration.AppData.Checkpoint index.json)
}

function Install-Update {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            Position = 0,
            ValueFromPipeline = $true)]
        [PSTypeName('PackageInfo')]
        [PSCustomObject]
            $Package
    )

    if ($Package -eq $null) {
        $installed = Get-Package -Repository Installed
    }
    else {
        $installed = $Package
    }

    # Search for updates
    $updates = New-Object System.Collections.ArrayList
    foreach ($pkg in $installed) {

        # Load Repository Configurations
        $local = Import-Configuration $Configuration.Repository[$pkg.Source]
        $remote = Import-Configuration $local.Remote

        # Validate Repositories are Synchronized
        if ($local.Revision -ne $remote.Revision) {
            Sync-Repository $pkg.Source | Out-Null
        }

        # Load Repository Index
        $index = Import-Index $local.Index

        # Load Latest Package Revision
        $source = $index.Packages[$pkg.Name]

        # Symantic Version Number Wrappers
        $CurrentVersion = New-VersionWrapper $pkg.Version
        $SourceVersion= New-VersionWrapper $source.Version

        # Compare versions to determine if update is necessary
        if ($CurrentVersion.Compare($SourceVersion) -eq -1) {
            [Void]$updates.Add($source)
        }
    }

    # Initiate Installation of Updates
    foreach ($pkg in $updates) {
        
        # Create restore checkpoint
        $checkpoint = Checkpoint-Package $pkg.Name

        # Initiate install
        if (! (Install-Package $pkg.Name $pkg.Repository -Update) ) {

            # Restore checkpoint on failure
            Restore-Package $checkpoint | Out-Null

            return $false
        }
    }

    return $true
}

function Uninstall-Update {
    throw (New-Object System.NotImplementedException)
}

function Restore-Package {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0)]
        [PSTypeName('PackageCheckpoint')]
        [PSCustomObject]
            $InputObject
    )

    $ExitState = $true
    $ExtractPath = Join-Path $Configuration.Appdata.Temp $InputObject.SHA1

    # Create temporary folder for package extraction
    New-Item $ExtractPath -ItemType Directory | Out-Null
    
    # Extract Checkpoint Archive Package
    if (!(Decompress-Archive $InputObject.Archive $ExtractPath)) {
        return $false
    }

    Push-Location $ExtractPath

    # Package Info object
    $package = Import-Configuration manifest.json
    Remove-Item manifest.json

    # Convert Manifest to Hashtable
    $manifest = @{}
    foreach ($file in $package.Manifest) {
        $manifest.Add($file.SHA1, $file.Path)
    }

    # Extraction path expression for path transformation
    $RelativePathExpression = [System.Text.RegularExpressions.Regex]::Escape($ExtractPath)

    # Secure Hash Helper Object
    $sha1 = Get-SecureHashProvider

    try {
        foreach ($f in (Get-ChildItem -Recurse -File)) {
            $destination = $manifest[$sha1.HashFile($f)]
        
            Copy-Item $f.FullName $destination -Force
        }
    }
    catch {
        Write-Error "[$($manifest.Name)] Restoration failed and the package files may have been left in an inconsistent state."
        $ExitState = $false
    }

    Pop-Location
    Remove-Item $ExtractPath

    return $ExitState
}

function Get-Package {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            Position = 0,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('Name')]
        [String]
            $Package,

        [Parameter(
            Mandatory = $false,
            Position = 1,
            ValueFromPipelineByPropertyName = $true)]
        [String]
            $Repository
    )

    # List all Packages
    if ([String]::IsNullOrEmpty($Package)) {

        # All Repositories
        if ([String]::IsNullOrEmpty($Repository)) {

            foreach ($repo in $Configuration.Repository.GetEnumerator()) {
                $Config = Import-Configuration $repo.Value
                $Index = Import-Index $Config.Index

                foreach ($pkg in $Index.Packages.GetEnumerator()) {
                    Write-Output ([PSCustomObject]$pkg.Value)
                }
            }
            return
        }

        # Specified Repository Only
        $Config = Import-Configuration $Configuration.Repository[$Repository]
        $Index = Import-Index $Config.Index
        foreach ($pkg in $Index.Packages.GetEnumerator()) {
            Write-Output ([PSCustomObject]$pkg.Value)
        }
        return
    }

    # Search All Repositories for Package
    elseif ([String]::IsNullOrEmpty($Repository)) {
        return (Find-Package $Package)
    }

    # Search Valid Repository for Package
    elseif ($Configuration.Repository.ContainsKey($Repository)) {
        $Config = Import-Configuration $Configuration.Repository[$Repository]
        $Index = Import-Index $Config.Index
        return [PSCustomObject]$Index.Packages[$Package]
    }

    # Failed to locate repository
    if ($Configuration.Repository.ContainsKey($Repository)) {
        Write-Error "$Repository could not be found."
    }

    # Failed to locate package
    if ($Index.Packages.ContainsKey($Package)) {
        Write-Error "$Package could not be found. Try updating the package list from the remote repository."
    }
}

function Find-Package {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0)]
        [String]
            $Package,

        [Parameter(Mandatory = $false)]
        [Switch]
            $Remote
    )

    foreach ($repo in $Configuration.Repository.GetEnumerator()) {
        if ($Remote -and $repo.Key -eq 'Installed') {
            continue
        }

        $repository = Import-Configuration $repo.Value
        $index = Import-Index $repository.Index
        if ($index.Packages.ContainsKey($Package)) {
            Write-Output ([PSCustomObject]$index.Packages[$Package])
        }
    }
}

function Publish-Package {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateScript({Test-Path $_ -PathType Leaf -and (Split-Path $_ -Leaf) -eq '.package-conf.json'})]
        [Alias('Path', 'FullName')]
        [String]
            $LiteralPath
    )

    # Secure Hashing Algorithm Helper
    $sha1 = Get-SecureHashProvider

    ###############################################################################
    # Process Package Content

    # Import Package Configuration
    $PackageConfiguration = ConvertFrom-Json ([String](Get-Content $LiteralPath))

    # Create Package Archive File & Build Manifest
    $ArchivePath = Join-Path $InvocationPath ($PackageConfiguration.Name + ".zip")
    $archive = [System.IO.Compression.ZipFile]::Open($ArchivePath, 1)
    $archive.Dispose()

    # Open Archive for Writing
    $archive = [System.IO.Compression.ZipFile]::Open($ArchivePath, 2)

    $manifest = New-Object System.Collections.ArrayList
    $RelativePathExpression = [System.Text.RegularExpressions.Regex]::Escape($PackageConfiguration.Root)

    # Process Files and Store in Package Archive
    foreach ($f in (Get-ChildItem $PackageConfiguration.Root -File -Recurse)) {
        $skip = $false

        # Ignore Autogenerated Archive File
        if ($f.FullName -eq $ArchivePath) {
            continue
        }

        # Check Ignore List
        foreach ($regex in $PackageConfiguration.Ignore) {
            if ($f.Name -match $regex) {
                $skip = $true
                break
            }
        }

        # Ignore File
        if ($skip) {
            continue
        }

        # Process File
        $file = [PSCustomObject]@{
            Path = ($f.FullName -replace $RelativePathExpression, [String]::Empty)
            SHA1 = $sha1.HashFile($f)
        }
        [void]$manifest.Add($file)
        Add-ArchiveEntry -Path $f.FullName -EntryPath $file.Path -Archive $archive
    }

    # Close Archive File
    $archive.Dispose()

    $repository = ConvertFrom-Json ([String](Get-Content $PackageConfiguration.Repository))

    # Build Package Object
    $params = @{
        Name = $PackageConfiguration.Name
        SHA1 = $sha1.HashFile( (Get-Item -LiteralPath $ArchivePath) )
        Version = $PackageConfiguration.Version
        Install = "& .\install.ps1"
        Uninstall = [string]::Empty
        Path = Join-Path (Split-Path $PackageConfiguration.Repository -Parent) (Split-Path $ArchivePath -Leaf)
        Repository = $repository.Name
        Manifest = $manifest
        Dependency = $PackageConfiguration.Dependency
    }
    $package = New-Package @params

    # Register Package with Repository
    if (Register-Package $package $repository.Path) {
        Move-Item $ArchivePath (Split-Path $PackageConfiguration.repository -Parent) -Force
    }
    else {
        Write-Error "Package registration failed."
        Remove-Item $ArchivePath
    }
}

# Public Object Constructors

function New-Repository {
    [CmdletBinding()]
    param(
        # Common name of the repository [Recommend No Whitespace Characters].
        [Parameter(Mandatory = $true)]
        [String]
            $Name,
                
        # Local repository root path.
        [Parameter(Mandatory = $true)]
        [String]
            $Local,

        # Remote repository config path.
        [Parameter(Mandatory = $false)]
        [String]
            $Remote = [String]::Empty,

        # Incremental revision number of the index. Used to determine if the repository needs to be updated.
        [Parameter(Mandatory = $false)]
        [Int]
            $Revision = 0,

        # Remote repository path type. Reserved for future repository types (e.g. SharePoint, SFTP, SourceForge, GitHub...)
        [Parameter(Mandatory = $false)]
        [ValidateSet('UNC')]
        [String]
            $Type = 'UNC',

        # PackageManager version supported.
        [Parameter(Mandatory = $false)]
        [String]
            $Version = $ModuleVersion
    )

    $repository = @{
        # The name of the repository [Recommend No Whitespace Characters]
        Name     = $Name.Trim()
        Path     = Join-Path $Local conf.json
        Local    = $Local
        Remote   = $Remote
        Revision = $Revision
        Type     = $Type
        Version  = $Version
        Index    = Join-Path $Local index.json
    }

    return $repository
}

function New-Package {
    [CmdletBinding()]
    param(
        # Package Name
        [Parameter(Mandatory = $true)]
        [String]
            $Name,

        # Package File Secure Hash Algorithm 1 String
        [Parameter(Mandatory = $true)]
        [String]
            $SHA1,

        # Package Version
        [Parameter(Mandatory = $true)]
        [String]
            $Version,

        # Install Expression
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]
            $Install,

        # Update Expression
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]
            $Update,

        # Uninstall Expression
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]
            $Uninstall,

        # Package Archive File Path
        [Parameter(Mandatory = $true)]
        [String]
            $Path,
        
        # Repository Name Where the Source Package is Published
        [Parameter(Mandatory = $true)]
        [String]
            $Source,

        # Repository Name of Where this Package Information is Registered
        [Parameter(Mandatory = $true)]
        [String]
            $Repository,

        # Package File Manifest
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]
            $Manifest,

        # Package Dependency Manifest
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]
            $Dependency
    )

    $package = [PSCustomObject]@{
        Name       = $Name
        SHA1       = $SHA1
        Version    = $Version
        Install    = $Install
        Uninstall  = $Uninstall
        Path       = $Path
        Source     = $Source
        Repository = $Repository
        Manifest   = $Manifest
        Dependency = $Dependency
    }

    [Void]$package.PSObject.TypeNames.Insert(0, 'PackageInfo')

    # Sort Order Comparison
    Add-Member -InputObject $package -MemberType ScriptMethod -Name Compare -Value {
        param([Object]$package)
        $verCurrent = New-VersionWrapper $this.Version
        $verPackage = New-VersionWrapper $package.Version

        if ($this.Name -ne $package.Name) {
            Write-Error ("Invalid comparison. [{0}] to [{1}]." -f $this.Name, $package.Name)
            return -2
        }

        return $verCurrent.Compare($verPackage)
    }

    return $package
}

function New-PackageConfiguration {
    param(
        # The name of the new package
        [Parameter(
            Mandatory = $true,
            Position = 0)]
        [ValidateScript({$_ -notmatch ([System.Text.RegularExpressions.Regex]::Escape(([System.IO.Path]::GetInvalidFileNameChars() -join [String]::Empty)))})]
        [String]
            $Name,

        # The literal path to the root directory containing the source files of the new package
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [Alias('FullName')]
        [ValidateScript({Test-Path -LiteralPath $_})]
        [String]
            $LiteralPath,

        # The literal path to the configuration file of the repository used for publishing this package
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [ValidateScript({Test-Path -LiteralPath $_})]
        [String]
            $Repository
    )

    # Basic package configuration
    $PackageConfig = @{
        # Package name
        Name        = $Name

        # Root directory containing the source files for the package
        Root        = $LiteralPath

        # Symantic version number of the package
        Version     = "1.0.0"

        # Path to the configuration file for the publishing repository
        Repository  = $Repository

        # Default installation target directory
        TargetPath  = [String]::Empty

        # List of files to be removed from the source files when publishing the package
        Clean       = New-Object System.Collections.ArrayList

        # List of files to be ignored from the source files when publishing the package
        Ignore      = New-Object System.Collections.ArrayList

        # List of external packages that must be installed to support this package
        Dependency  = New-Object System.Collections.ArrayList
    }

    # Always default to major version 1
    $PackageVersion = @{
        Date = (Get-Date).ToShortDateString()
        Major = 1
        Minor = 1
        Patch = 7
    }

    # Set ignore for default hook scripts
    [void]$PackageConfig.ignore.Add("publish-package.ps1")
    [void]$PackageConfig.ignore.Add("version-bump.ps1")

    # Write Configuration
    ConvertTo-Json $PackageConfig -Depth 10 > .package-conf.json
    ConvertTo-Json $PackageVersion -Depth 10 > .package-version.json

    # Copy utility hook scripts
    Copy-Item (Join-Path $Configuration.Hooks publish-package.ps1) (Join-Path $LiteralPath publish-package.ps1)
    Copy-Item (Join-Path $Configuration.Hooks version-bump.ps1) (Join-Path $LiteralPath version-bump.ps1)
}

# General Utility Functions

function Add-ArchiveEntry {
    param(
        # Source File Path
        [Parameter(Mandatory = $true)]
        [String]
            $Path,

        [Parameter(Mandatory = $true)]
        [String]
            $EntryPath,

        # Destination Zip Archive File
        [Parameter(Mandatory = $true)]
        [System.IO.Compression.ZipArchive]
            $Archive
    )
    # Create File Entry
    $EntryPath = $EntryPath -replace "\\", "/" -replace "^/", ""
    $entry = $Archive.CreateEntry($EntryPath)

    # Open Streams
    $read  = [System.IO.StreamReader]$Path
    $write = [System.IO.StreamWriter]$entry.Open()

    # Write Data to Archive
    $read.BaseStream.CopyTo($write.BaseStream)
    $write.Flush()

    # Close Streams
    $read.Close()
    $write.Close()
}

function Get-SecureHashProvider {
    $provider = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider

    Add-Member -InputObject $provider -MemberType ScriptMethod -Name HashFile -Value {
        param(
            [Parameter(Mandatory = $true)]
            [System.IO.FileInfo]
                $File
        )
        $reader = [System.IO.StreamReader]$File.FullName
        [void] $this.ComputeHash( $reader.BaseStream )

        $reader.Close()

        return $this.OutString
    }

    Add-Member -InputObject $provider -MemberType ScriptProperty -Name OutString -Value {
        $hash = $this.Hash | %{"{0:x2}" -f $_}
        return ($hash -join "")
    }

    return $provider
}

function New-VersionWrapper {
    param(
        [Parameter(Mandatory = $true)]
            [String]
            $VersionString
    )
    $Component = $VersionString.Split('.')
    $VersionWrapper = [PSCustomObject]@{
        Major = [Int]$Component[0]
        Minor = [Int]$Component[1]
        Patch = [Int]$Component[2]
    }

    Add-Member -InputObject $VersionWrapper -MemberType ScriptProperty -Name Version -Value {
        return ("{0}.{1}.{2}" -f $this.Major, $this.Minor, $this.Patch)
    }

    Add-Member -InputObject $VersionWrapper -MemberType ScriptMethod -Name Compare -Value {
        param(
            [Parameter(Mandatory = $true)]
                [Object]
                $Version
        )
        # Returns one of 3 values that indicates the sort order of the current version versus the
        # version number being compared against. 1 = greater, 0 = equivalent, -1 = lesser
        if ($this.Major -gt $Version.Major) {
            return 1
        }
        elseif ($this.Major -lt $Version.Major) {
            return -1
        }

        if ($this.Minor -gt $Version.Minor) {
            return 1
        }
        elseif ($this.Minor -lt $Version.Minor) {
            return -1
        }

        if ($this.Patch -gt $Version.Patch) {
            return 1
        }
        elseif ($this.Patch -lt $Version.Patch) {
            return -1
        }
        return 0
    }

    return $VersionWrapper
}

Export-ModuleMember -Function *

###############################################################################
###############################################################################
## SECTION 02 ## PRIVATE FUNCTIONS
##
## No function or variable in this section is exported unless done so by an
## explicit call to Export-ModuleMember
###############################################################################
###############################################################################

# Configuration Management

function Initialize-Module {
    [CmdletBinding()]
    param (
        [Parameter()]
        [Switch]
            $Silent,

        [Parameter()]
        [Switch]
            $Force
    )

    $UserData = Join-Path $env:APPDATA PackageManager

    if ($Force) {
        $initialized = $false
    }
    else {
        $initialized = Test-Path (Join-Path $UserData conf.json) -PathType Leaf
        $UserDataExists = Test-Path $UserData
    }

    if ($initialized -or $UserDataExists) {
        if ($Silent) {
            # Fail with error.
            Write-Error "Module is already initialized."
            return
        }
        Write-Warning "Module initialization will overwrite configuration files, and may cause the loss of package state information for installed packages."
    }
    
    $prompt = !$Silent
    while ($prompt) {
        Write-Host "Continue with initialization (Y/N): " -NoNewline -ForegroundColor DarkYellow
        $response = Read-Host -Prompt "Y"
        if ([String]::IsNullOrEmpty($response)) {
            $response = 'y'
        }
        switch ($response.ToLower().Trim()) {
            'y' {
                $prompt = $false
            }

            'n' {
                return
            }

            default {
                Write-Host 'Invalid input.' -ForegroundColor DarkRed
            }
        }
    }

    # Instantiate new configuration
    $Script:Configuration = New-ModuleConfiguration

    # Remove Old Configuration
    if ($UserDataExists) {
        # Remove Data Files
        Get-ChildItem $Configuration.AppData.Root -File -Recurse | Remove-Item

        # Remove Repositories
        Get-ChildItem $Configuration.AppData.Repository -Directory |
            Where-Object {$_.Name -ne 'installed'} |
                Remove-Item
    }
    else {
        New-Item $Configuration.AppData.Root -ItemType Directory       | Out-Null
        New-Item $Configuration.AppData.Temp -ItemType Directory       | Out-Null
        New-Item $Configuration.AppData.Repository -ItemType Directory | Out-Null
        New-Item $Configuration.AppData.Checkpoint -ItemType Directory | Out-Null

        # Instantiate Installed Repository folder
        New-Item (Join-Path $configuration.AppData.Repository installed) -ItemType Directory | Out-Null
    }

    # Save new-configuration
    Write-Configuration $Configuration $Configuration.Path

    # Configure Default Installed Repository
    $params = @{
        Name = 'Installed'
        Local = Join-Path $Configuration.AppData.Repository installed
    }
    $repository = New-Repository @params
    Write-Configuration $repository $repository.Path

    $params = @{
        Name = 'Installed'
        Path = $repository.Index
    }
    $index = New-Index @params
    Write-Configuration $index $index.Path

    # Configure Checkpoint Index
    $index = New-CheckpointIndex
    Write-Configuration $index $index.Path

    Write-Verbose "PackageManager module initialized."
}

function Import-Configuration {
    param(
        [Parameter(Mandatory = $true)]
        [String]
            $Path,

        [Parameter(
            Mandatory = $false)]
        [Switch]
            $Module
    )
    $Imported = Import-Json $Path

    # Configuration File Version Support
    $ImportedVersion = New-VersionWrapper $Imported.Version
    $CurrentVersion = New-VersionWrapper $ModuleVersion

    if ($CurrentVersion.Compare($ImportedVersion) -ne 0) {
        Write-Warning "Imported configuration version does not match the current module version."
    }

    # Convert Repository Listing to a Hashtable
    if($Module) {
        $Repository = ConvertTo-Hashtable $Imported.Repository
        $Imported.PSObject.Properties.Remove('Repository')
        Add-Member -InputObject $Imported -MemberType NoteProperty -Name Repository -Value $Repository
    }

    if ($CurrentVersion.Major -eq $ImportedVersion.Major) {
        return $Imported
    }
    else {
        Write-Error ("Imported configuration file version [{0}] not supported. Current module version [{1}]." -f $ImportedVersion.Version, $CurrentVersion.Version)
        return $null
    }
}

# Index Management

function Import-Index {
    param(
        [Parameter(Mandatory = $true)]
        [String]
            $Path
    )

    $Index = Import-Json $Path

    # Convert Packages Property to Hashtable
    $Packages = ConvertTo-Hashtable $Index.Packages
    $Index.PSObject.Properties.Remove('Packages')

    # Reappend Packages Hashtable
    Add-Member -InputObject $Index -MemberType NoteProperty -Name Packages -Value $Packages

    # Add Custom Type Information to index packages
    foreach ($pkg in $Index.Packages.GetEnumerator()) {
        $pkg.Value.PSObject.TypeNames.Insert(0, 'PackageInfo')
    }

    return $Index
}

function Import-Checkpoint {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path $_})]
        [String]
            $Path
    )

    $Index = Import-Json $Path

    # Convert Index to Hashtable
    $Index = ConvertTo-Hashtable $Index

    $Editable = @{}

    # Add Custom Type information to checkpoint entries
    foreach($registry in $Index.GetEnumerator()) {
        
        # Process checkpoints for the package registry
        foreach ($checkpoint in $registry.Value) {
            $checkpoint.PSObject.TypeNames.Insert(0, 'PackageCheckpoint')
        }

        # Convert the list back to an ArrayList
        $list = New-Object System.Collections.ArrayList

        [Void]$list.AddRange($registry.Value)
        $Editable[$registry.Key] = $list
    }

    return $Editable
}

# Package Management

function Auto-Install {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0)]
        [PSTypeName('PackageInfo')]
        [PSCustomObject]
            $Package,

        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [ValidateScript({Test-Path $_})]
        [String]
            $Path,

        [Parameter(
            Mandatory = $true,
            Position = 2)]
        [AllowNull()]
        [PSCustomObject]
            $Extended
    )

    # Move working directory to extracted package content
    Push-Location $Path

    ###############################################################################
    # Load Package Configuration
    try {
        $InstallConfiguration = ConvertFrom-Json ([String](Get-Content .package-conf.json))
        $SourceRepository = ConvertFrom-Json ([String](Get-Content $InstallConfiguration.repository))
    }
    catch {
        Write-Error "Package configuration missing or corrupt."

        # Return to previous working directory
        Pop-Location
        Remove-Item $Path

        return $false
    }

    # Get Installation Directory
    if ($InstallConfiguration.TargetPath) {
        $InstallationPath = Invoke-Expression ("`"{0}`"" -f $InstallConfiguration.TargetPath)
    }
    else {
        $InstallationPath = Read-Host -Prompt "Enter installation directory:"
    }

    # Prepare Installation Directory
    if (!(Test-Path $InstallationPath)) {
        try {
            New-Item $InstallationPath -ItemType Directory | Out-Null
        }
        catch {
            Write-Error "Invalid path [$InstallationPath]."
            return $false
        }
    }

    $PathExpression = [System.Text.RegularExpressions.Regex]::Escape($Path)
    $sha1 = Get-SecureHashProvider

    # Installed File Manifest
    $manifest = New-Object System.Collections.ArrayList

    foreach ($f in (Get-ChildItem * -File -Exclude install.ps1 -Recurse)) {
        # Set Destination Path
        $destination = $f.FullName -replace $PathExpression, $InstallationPath

        # Record the file for the installed manifest
        $file = [PSCustomObject]@{
            Path = $destination
            SHA1 = $sha1.HashFile($f)
        }
        [Void] $manifest.Add($file)

        # Verify Destination Directory Exists
        if (!(Test-Path (Split-Path $destination -Parent))){
            New-Item (Split-Path $destination -Parent) -ItemType Directory | Out-Null
        }

        # Move the file to installation destination
        Copy-Item $f.FullName -Destination $destination -Force | Out-Null
    }

    $params = @{
        Name       = $InstallConfiguration.Name
        SHA1       = $Package.SHA1
        Version    = $InstallConfiguration.Version
        Install    = [String]::Empty
        Update     = $Package.Update
        Uninstall  = $Package.Uninstall
        Path       = $InstallationPath
        Source     = $SourceRepository.Name
        Repository = 'Installed'
        Manifest   = $manifest
        Dependency = $InstallConfiguration.Dependency
    }

    # Return to previous working directory
    Pop-Location

    $installed = New-Package @params
    Add-Member -InputObject $installed -MemberType NoteProperty -Name Extended -Value $Extended

    if (Register-Package $installed $Configuration.Repository['Installed']) {
        # Return Success
        return $true
    }
    else {
        Write-Host "Rolling back installation."
        if ($Package.Uninstall) {
            & $Package.Uninstall $Extended
        }

        # Undo Installation and Return Failed
        foreach ($f in $manifest) {
            Remove-Item $f.Path
        }
        return $false
    }
}

function Auto-Uninstall {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ParameterSetName = 'Object')]
        [PSTypeName('PackageInfo')]
        [PSCustomObject]
            $InputObject,

        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'String')]
        [String]
            $Package
    )

    $Installed = @{}
    $Installed.Configuration = Import-Configuration $Configuration.Repository['Installed']
    $Installed.Index = Import-Configuration $Installed.Configuration.Index

    if (!$InputObject) {
        $InputObject = Get-Package $Package Installed
    }

    if (!$Installed.Index.Packages.ContainsKey($InputObject.Name)) {
        return $true
    }

    # WARNING: This could be very dangerous, and possibly break someones computer!
    try {
        Remove-Item $InputObject.Path -Recurse -Force
    }
    catch {
        Write-Host $_ -ForegroundColor Red
        return $false
    }

    return $true
}

function Extract-Package {
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0)]
        [Object]
            $Package,

        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [String]
            $Destination
    )

    # SHA1 Generator
    $sha1 = Get-SecureHashProvider

    # Download Package File
    $archive = Join-Path $Destination (Split-Path $Package.Path -Leaf)
    Copy-Item $pkg.Path $archive

    # Extract Package Content
    $success = Decompress-Archive $archive $Destination
    Remove-Item $archive

    if (!$success) {
        return $false
    }
    
    # Convert Manifest to Hashtable
    $manifest = @{}
    foreach ($file in $Package.Manifest) {
        $manifest.Add($file.SHA1, $file.Path)
    }

    # Validate Manifest
    $Valid = $true
    foreach ($f in (Get-ChildItem "$Destination\*" -Recurse -File)) {
        
        # Validate File Secure Hash
        if (!$manifest.ContainsKey( $sha1.HashFile($f) )) {
            Write-Error ("{0} contents do not match the manifest.  File may be corrupt." -f $f.FullName)
            $Valid = $false
        }
    }

    $sha1.Clear()
    $sha1.Dispose()

    return $Valid
}

function Checkpoint-Package {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]
            $Package
    )

    $pkg = Get-Package $Package 'Installed'

    if ($pkg -eq $null) {
        Write-Error "Backup Failed! $Package could not be located." -ErrorAction Stop
    }

    # Load the checkpoint index
    $CheckpointPath = (Join-Path $Configuration.AppData.Checkpoint index.json)
    $index = Import-Index $CheckpointPath

    # Get | Create Package Checkpoint Registry
    if (!$index.Packages.ContainsKey($pkg.Name)) {
        $index.Packages.Add($pkg.Name, (New-Object System.Collections.ArrayList))
    }

    # Get the package checkpoint registry
    $registry = New-Object System.Collections.ArrayList
    $registry.AddRange($index.Packages[$pkg.Name])

    # Destination checkpoint archive path
    $ArchivePath = (Join-Path $Configuration.AppData.Checkpoint ("{0}.zip" -f $pkg.SHA1))

    # Remove previous checkpoints of the same package version
    $registered = $registry | Where-Object {$_.SHA1 -eq $pkg.SHA1}
    if ($registered -and [System.IO.File]::Exists($registered.Archive)) {
        Remove-Item $registered.Archive
        $registry.Remove($registered)
    }

    # Create Checkpoint Archive
    $archive = [System.IO.Compression.ZipFile]::Open($ArchivePath, 'Create')
    $archive.Dispose()

    $archive = [System.IO.Compression.ZipFile]::Open($ArchivePath, 'Update')

    # Write Data to Checkpoint Archive
    $entry = $archive.CreateEntry('manifest.json')
    $write = [System.IO.StreamWriter]$entry.Open()
    $write.Write( (ConvertTo-Json $pkg) )
    $write.Flush()
    $write.Close()

    # Write installed package files to the checkpoint archive
    $RelativePathExpression = [System.Text.RegularExpressions.Regex]::Escape($pkg.Path)
    foreach ($f in $pkg.Manifest) {
        $RelativePath = $f.Path -replace $RelativePathExpression, [String]::Empty
        Add-ArchiveEntry $f.Path $RelativePath $archive
    }
    $archive.Dispose()

    # Create the new checkpoint record
    $checkpoint = New-Checkpoint $pkg $ArchivePath

    # Add the record to the package's registry
    [Void] $registry.Add($checkpoint)
    $index.Packages[$pkg.Name] = $registry.ToArray()

    # Save the modified checkpoint index
    Write-Configuration $index $CheckpointPath

    return $checkpoint
}

function Serialize-Package {
    param(
        [Parameter(Mandatory = $true)]
        [Object]
            $Package
    )

    # Build Field List
    $serialized = ConvertTo-Hashtable $Package

    return $serialized
}

# Private Object Constructors

function New-ModuleConfiguration {
    
    # Default user data cache
    $UserData = Join-Path $env:APPDATA PackageManager
    
    $conf = @{}
    $conf.Path    = Join-Path $UserData conf.json
    $conf.Version = $ModuleVersion
    $conf.Hook    = Join-Path $ModuleInvocationPath hook
    $conf.AppData = @{}
    $conf.AppData.Root       = $UserData
    $conf.AppData.Temp       = Join-Path $conf.AppData.Root temp
    $conf.AppData.Repository = Join-Path $conf.AppData.Root repository
    $conf.AppData.Checkpoint = Join-Path $conf.AppData.Root checkpoint
    $conf.Repository = @{}
    $conf.Repository.Installed = Join-Path (Join-Path $conf.AppData.Repository installed) conf.json

    return $conf
}

function New-Index {
    param(
        # Common name of the repository.
        [Parameter(Mandatory = $true)]
        [String]
            $Name,

        # File path of the index file.
        [Parameter(Mandatory = $true)]
        [String]
            $Path,
                
        # Incremental revision number of the index. Used to determine if the index needs to be updated.
        [Parameter(Mandatory = $false)]
        [Int]
            $Revision = 0,
        
        # PackageManager version supported.
        [Parameter(Mandatory = $false)]
        [String]
            $Version = $ModuleVersion
    )

    $index = @{
        Name = $Name
        Path = $Path
        Revision = $Revision
        Version = $Version
        Packages = @{}
    }
    return $index
}

function New-Checkpoint {
    [CmdletBinding()]
    param(
        # Package name
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = 'Object')]
        [PSTypeName('PackageInfo')]
        [PSCustomObject]
            $InputObject,

        # Package name
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = 'String')]
        [String]
            $Package,

        # Semantic version number
        [Parameter(
            Mandatory = $true,
            Position = 1,
            ParameterSetName = 'String')]
        [String]
            $Version,

        # Secure Hash Algorithm String
        [Parameter(
            Mandatory = $true,
            Position = 2,
            ParameterSetName = 'String')]
        [String]
            $SHA1,

        # Arhive zip file name
        [Parameter(
            Mandatory = $true,
            Position = 1,
            ParameterSetName = 'Object')]
        [Parameter(
            Mandatory = $true,
            Position = 3,
            ParameterSetName = 'String')]
        [String]
            $Archive
    )

    if ($PSCmdlet.ParameterSetName -eq 'Object') {
        $Package = $InputObject.Name
        $Version = $InputObject.Version
        $SHA1    = $InputObject.SHA1
    }

    $checkpoint = [PSCustomObject]@{
        Package = $Package
        Version = $Version
        SHA1    = $SHA1
        Archive = $Archive
    }

    $checkpoint.PSObject.TypeNames.Insert(0, 'PackageCheckpoint')

    return $checkpoint
}

function New-CheckpointIndex {
    $index = @{
        Name = 'Checkpoint'
        Path = "$HOME\AppData\Roaming\PackageManager\checkpoint\index.json"
        Revision = 0
        Version = '1.0.0'
        Packages = New-Object System.Collections.ArrayList
    }
    return $index
}

# General Utilities

function Import-Json {
    param(
        [Parameter(Mandatory = $true)]
            [String]
            $Path
    )
    [String]$json = Get-Content $Path
    return (ConvertFrom-Json $json)
}

function Decompress-Archive {
    param(
        [Parameter(Mandatory = $true)]
            [String]
            $Source,

        [Parameter(Mandatory = $true)]
            [String]
            $Destination
    )

    try {
        [System.IO.Compression.ZipFile]::ExtractToDirectory($Source, $Destination)
    }
    catch {
        Write-Error "Extraction failed."
        return $false
    }

    return $true
}

function ConvertTo-Hashtable {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]
            $Object
    )
    $table = @{}

    foreach ($property in $Object.PSObject.Properties) {
        $table.Add($property.Name, $property.Value)
    }

    return $table
}

###############################################################################
###############################################################################
## SECTION 03 ## MODULE INITIALIZATION
##
## No function or variable in this section is exported unless done so by an
## explicit call to Export-ModuleMember
###############################################################################
###############################################################################
$ModuleInvocationPath  = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Definition)
$ModuleVersion = $null
$Configuration = $null

& {
    $ModuleManifest = Import-LocalizedData -BaseDirectory $ModuleInvocationPath -FileName PackageManager.psd1
    $Script:ModuleVersion = $ModuleManifest.ModuleVersion

    $UserData = Join-Path $env:APPDATA PackageManager

    if (Test-Path (Join-Path $UserData 'conf.json')) {
        $Script:Configuration = Import-Configuration (Join-Path $UserData 'conf.json') -Module
    }
    else {
        Initialize-Module
    }
} | Out-Null