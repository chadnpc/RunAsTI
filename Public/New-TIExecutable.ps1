function New-TIExecutable {
    [CmdletBinding()]
    param (
        
    )
    
    begin {
        $src = ([IO.Path]::Combine((Get-ModulePath RunAsTI), (Read-ModuleData RunAsTI).ModuleVersion, "Private"))
        $exc = $null
    }
    
    process {
        Push-Location $src
        try {
            go build
            $exc = Get-ChildItem -Path $src -Filter "ti.exe" -ErrorAction Stop
        } catch {
            $PSCmdlet.thorowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    $_,
                    'NewTIError',
                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                    $src
                )
            )
        }
        finally {
            Pop-Location
        }
        
    }
    
    end {
        return $exc
    }
}