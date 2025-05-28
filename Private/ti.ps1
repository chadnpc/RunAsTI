function New-TIExecutable {
    <#
    .SYNOPSIS
        creates a new TI executable from the source code in the module
    #>
    [CmdletBinding()][OutputType([IO.FileInfo])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrWhiteSpace()]
        [string]$executable,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Arguments,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$SourcePath = ([IO.Path]::Combine((Get-ModulePath RunAsTI), (Read-ModuleData RunAsTI).ModuleVersion, "Private"))
    )
    
    begin {
        $exc = $null
    }
    
    process {
        Push-Location $SourcePath
        try {
            $tmpfile = [IO.Path]::Combine($SourcePath, "ti.go")
            $mainfile = [IO.Path]::Combine($SourcePath, "main.go")
            $template = [IO.File]::ReadAllText($tmpfile)

            $main = $template.Replace("<EXECUTABLE>", $executable).Replace("<ARGUMENTS>", ($arguments -join '", "'))
            [void][IO.File]::WriteAllText($mainfile, $main)
            Remove-Item $tmpfile | Out-Null
            go build # This builds main.go into ti.exe in the current directory ($SourcePath)
            Remove-Item $mainfile | Out-Null
            [void][IO.File]::WriteAllText($tmpfile, $template) # Restore ti.go template
            $exc = Get-ChildItem -Path $SourcePath -Filter "ti.exe" -ErrorAction Stop
        } catch {
            $PSCmdlet.throwTerminatingError( # Fixed typo: thorowTerminatingError -> throwTerminatingError
                [System.Management.Automation.ErrorRecord]::new(
                    $_,
                    'NewTIError',
                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                    $SourcePath # Fixed undefined variable: $src -> $SourcePath
                )
            )
        }
        finally {
            Pop-Location
        }
        
    }
    
    end {
        return [IO.FileInfo]::New($exc)
    }
}