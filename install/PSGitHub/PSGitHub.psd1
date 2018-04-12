#
# Module manifest for module 'PSGitHub'
#
# Generated by: Trevor Sullivan <trevor@trevorsullivan.net>
#
# Generated on: 3/15/2016
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'PSGitHub.psm1'

# Version number of this module.
ModuleVersion = '0.14'

# ID used to uniquely identify this module
GUID = '763b7f83-ea98-4424-8e09-cd336a4c1c58'

# Author of this module
Author = 'Trevor Sullivan <trevor@trevorsullivan.net>'

# Company or vendor of this module
CompanyName = 'Trevor Sullivan'

# Copyright statement for this module
Copyright = 'Trevor Sullivan'

# Description of the functionality provided by this module
Description = 'This PowerShell module enables integration with GitHub.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module
FunctionsToExport = @(

    ### GitHub Authentication and Account commands
    'Get-GitHubAuthenticatedUser',
    'Set-GitHubAuthenticatedUser',
    'Set-GitHubToken'

    ### GitHub Repository commands
    'New-GitHubRepository',
    'Remove-GitHubRepository',
    'Find-GitHubRepository',
    'Get-GitHubRepository'

    ### GitHub Issue commands
    'New-GitHubIssue',
    'Set-GitHubIssue',
    'Get-GitHubMilestone',
    'Get-GitHubAssignee',
    'Test-GitHubAssignee',
    'Get-GitHubIssue',

    ### GitHub Comment commands
    'Get-GitHubComment',
    'New-GitHubComment',
    
    ### GitHub Release commands
    'Get-GitHubRelease',
    'New-GitHubRelease',
        
    ### GitHub Release commands
    'Get-GitHubReleaseAsset',
    'New-GitHubReleaseAsset',
    'Remove-GitHubReleaseAsset',
    
    ### GitHub Fork and Pull Request commands
    'New-GitHubFork',
    'New-GitHubPullRequest',

    ### GitHub Gist commands
    'New-GitHubGist',
    'Remove-GitHubGist',
    'Get-GitHubGist',
    'Save-GitHubGist',
    'Set-GitHubGist',

    ### Miscellaneous
    'Get-GitHubLicense'
    
    )

# Cmdlets to export from this module
#CmdletsToExport = ''

# Variables to export from this module
#VariablesToExport = ''

# Aliases to export from this module
#AliasesToExport = ''

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = 'Git', 'GitHub', 'Trevor Sullivan', 'Microsoft MVP', 'PSMVP'

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        ProjectUri = 'https://trevorsullivan.net'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = 'Added support for GitHub Gists, thanks to Thomas Malkewitz! @dotps1'

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}
