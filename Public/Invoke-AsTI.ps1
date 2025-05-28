function Invoke-AsTI {
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Default')][Alias('RunAsTI')]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullOrWhiteSpace()]
        [string]$executable = 'cmd.exe',

        # @(" ") will create an array with one empty string.
        # If ValidateNotNullOrEmpty requires content, this is necessary.
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string[]]$argumentList = @(" ")
    )
    
    process {
        # The $ti variable will now be a System.IO.FileInfo object, representing the ti.exe file.
        $ti = $(if ($argumentList.Count -eq 0 -and $executable -eq "cmd.exe") {
                New-TIExecutable -executable $executable -arguments @("/c", "start", "pwsh.exe")
            } else {
                New-TIExecutable -executable $executable -arguments $ArgumentList
            }
        )
        
        # Check if the generated TI executable file actually exists using its FullName.
        if (![IO.File]::Exists($ti.FullName)) { # Corrected: using $ti.FullName
            Write-Error "Failed to create temporary TI executable '$($ti.FullName)'. Cannot proceed."
            return
        }
        if ($PSCmdlet.ShouldProcess("$Executable $([string]::join(' ', $ArgumentList)) as TI", "Launch and monitor process")) {
            Write-Verbose "Prepared temporary TI executable: $($ti.FullName)" # Corrected: using $ti.FullName
            # Since $ti.exe contains the embedded executable and its arguments,
            # we just need to run ti.exe itself. No separate arguments are passed here.
            $process = $null
            try {
                # Launch the temporary TI executable (ti.exe).
                # -PassThru is essential to get the Process object to monitor its exit.
                # No ArgumentList is passed here, as the Go program has the target's arguments embedded.
                $process = Start-Process -FilePath $ti.FullName -PassThru -ErrorAction Stop
            } catch {
                Write-Error "Failed to start temporary TI executable '$($ti.FullName)': $_"
                # Attempt to clean up the temporary executable file even if launch fails
                if (Test-Path $ti.FullName) { # Corrected: using $ti.FullName
                    Write-Verbose "Attempting to clean up temporary TI executable '$($ti.FullName)' after failed launch." # Corrected
                    Remove-Item $ti.FullName -Force -ErrorAction SilentlyContinue # Corrected
                }
                return # Exit the function
            }

            Write-Verbose "TI executable process $($process.Id) started. Monitoring for exit..."

            # Create a unique SourceIdentifier for this event subscription.
            # This is important if you call Invoke-AsTI multiple times concurrently.
            $sourceIdentifier = "TIProcessExited_" + [Guid]::NewGuid().ToString("N")
            
            # Capture the path to the temporary file for the event handler's scope.
            # PowerShell closures allow the script block to access variables from its defining scope.
            $tiPathToDelete = $ti.FullName # Corrected: using $ti.FullName
            
            # Register for the Exited event of the launched process.
            # The Action script block will be executed when the process exits.
            Register-ObjectEvent `
                -InputObject $process `
                -EventName 'Exited' `
                -SourceIdentifier $sourceIdentifier `
                -Action {
                    param($Sender, $EventArgs) # These parameters are typically the event source and event arguments.
                    
                    # Inside the event handler, access $tiPathToDelete and $sourceIdentifier
                    # which were captured from the Invoke-AsTI function's scope (closure).
                    
                    Write-Host "Cleanup: Process $($Sender.Id) exited. Deleting temporary file '$tiPathToDelete'..."
                    
                    if (Test-Path $tiPathToDelete) {
                        try {
                            Remove-Item $tiPathToDelete -Force -ErrorAction Stop
                            Write-Host "Cleanup: Successfully deleted temporary TI executable: $tiPathToDelete"
                        } catch {
                            Write-Warning "Cleanup: Failed to delete temporary TI executable '$tiPathToDelete': $($_.Exception.Message)"
                        }
                    } else {
                        Write-Warning "Cleanup: Temporary TI executable '$tiPathToDelete' not found (possibly already deleted)."
                    }
                    
                    # Unregister the event subscription to prevent memory leaks and unnecessary event processing.
                    try {
                        Unregister-Event -SourceIdentifier $sourceIdentifier -ErrorAction Stop
                        Write-Host "Cleanup: Unregistered event subscription '$sourceIdentifier'."
                    } catch {
                        Write-Warning "Cleanup: Failed to unregister event '$sourceIdentifier': $($_.Exception.Message)"
                    }
                }

            Write-Verbose "Event handler registered for TI executable process $($process.Id)."
            
            # Return the Process object. This allows the caller to interact with the launched process,
            # e.g., to wait for it or get its exit code.
            return $process
        }
    }
    end {
        # The primary cleanup is handled by the event handler when the process exits.
        # This end block is typically for cleaning up other resources that are not
        # tied to the lifetime of the launched process.
    }
}