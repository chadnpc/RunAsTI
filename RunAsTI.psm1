﻿
#!/usr/bin/env pwsh
#requires -Modules PsModuleBase

#region    Classes
# Main class
class RunAsTI {
    static [void] Start() {
    }
}

#endregion Classes
# Types that will be available to users when they import the module.
$typestoExport = @(
    [RunAsTI]
)
$TypeAcceleratorsClass = [PsObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
foreach ($Type in $typestoExport) {
    if ($Type.FullName -in $TypeAcceleratorsClass::Get.Keys) {
        $Message = @(
            "Unable to register type accelerator '$($Type.FullName)'"
            'Accelerator already exists.'
        ) -join ' - '
        "TypeAcceleratorAlreadyExists $Message" | Write-Debug
    }
}
# Add type accelerators for every exportable type.
foreach ($Type in $typestoExport) {
    $TypeAcceleratorsClass::Add($Type.FullName, $Type)
}
# Remove type accelerators when the module is removed.
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    foreach ($Type in $typestoExport) {
        $TypeAcceleratorsClass::Remove($Type.FullName)
    }
}.GetNewClosure();

$scripts = @();
$Public = Get-ChildItem "$PSScriptRoot/Public" -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
$scripts += Get-ChildItem "$PSScriptRoot/Private" -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
$scripts += $Public

foreach ($file in $scripts) {
    try {
        if ([string]::IsNullOrWhiteSpace($file.fullname)) { continue }
        . "$($file.fullname)"
    }
    catch {
        Write-Warning "Failed to import function $($file.BaseName): $_"
        $host.UI.WriteErrorLine($_)
    }
}

$Param = @{
    Function = $Public.BaseName
    Cmdlet   = '*'
    Alias    = '*'
    Verbose  = $false
}
Export-ModuleMember @Param