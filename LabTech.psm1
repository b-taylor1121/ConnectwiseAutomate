<#
.SYNOPSIS
    This is a PowerShell Module for LabTech.
    labtechconsulting.com
    labtechsoftware.com
    msdn.microsoft.com/powershell


.DESCRIPTION
    This is a set of commandlets to interface with the LabTech Agent.
    Tested Versions: v10.5, v11, v12, v2019

.NOTES
    Version:        1.9.0
    Author:         Chris Taylor
    Website:        labtechconsulting.com
    Creation Date:  3/14/2016
    Purpose/Change: Initial script development

    Update Date: 6/1/2017
    Purpose/Change: Updates for better overall compatibility, including better support for PowerShell V2

    Update Date: 1/23/2018
    Purpose/Change: Updates to address 32-bit vs. 64-bit environments

    Update Date: 2/1/2018
    Purpose/Change: Updates for support of Proxy Settings. Enabled -WhatIf processing for many functions.

    Update Date: 8/7/2018
    Purpose/Change: Added support for TLS 1.2

    Update Date: 8/28/2018
    Purpose/Change: Added Update-LTService function

    Update Date: 2/26/2019
    Purpose/Change: Update to support 32-bit execution in 64-bit OS without SYSNATIVE redirection

    Update Date: 9/9/2020
    Purpose/Change: Update to support 64-bit OS without SYSNATIVE redirection (ARM64)
#>

If (-not ($PSVersionTable)) {Write-Warning 'PS1 Detected. PowerShell Version 2.0 or higher is required.';return}
ElseIf ($PSVersionTable.PSVersion.Major -lt 3 ) {Write-Verbose 'PS2 Detected. PowerShell Version 3.0 or higher may be required for full functionality.'}

#Module Version
$ModuleVersion = "1.9.0"
$ModuleGuid='f1f06c84-00c8-11ea-b6e8-000c29aaa7df'

If ($env:PROCESSOR_ARCHITEW6432 -match '64' -and [IntPtr]::Size -ne 8 -and $env:PROCESSOR_ARCHITEW6432 -ne 'ARM64') {
    Write-Warning '32-bit PowerShell session detected on 64-bit OS. Attempting to launch 64-Bit session to process commands.'
    $pshell="${env:windir}\SysNative\WindowsPowershell\v1.0\powershell.exe"
    If (!(Test-Path -Path $pshell)) {
        $pshell="${env:windir}\System32\WindowsPowershell\v1.0\powershell.exe"
        If ($Null -eq ([System.Management.Automation.PSTypeName]'Kernel32.Wow64').Type -or $Null -eq [Kernel32.Wow64].GetMethod('Wow64DisableWow64FsRedirection')) {
            Write-Debug 'Loading WOW64Redirection functions'

            Add-Type -Name Wow64 -Namespace Kernel32 -Debug:$False -MemberDefinition @"
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool Wow64DisableWow64FsRedirection(ref IntPtr ptr);

[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool Wow64RevertWow64FsRedirection(ref IntPtr ptr);
"@
        }
        Write-Verbose 'System32 path is redirected. Disabling redirection.'
        [ref]$ptr = New-Object System.IntPtr
        $Result = [Kernel32.Wow64]::Wow64DisableWow64FsRedirection($ptr)
        $FSRedirectionDisabled=$True
    }#End If

    If ($myInvocation.Line) {
        &"$pshell" -NonInteractive -NoProfile $myInvocation.Line
    } Elseif ($myInvocation.InvocationName) {
        &"$pshell" -NonInteractive -NoProfile -File "$($myInvocation.InvocationName)" $args
    } Else {
        &"$pshell" -NonInteractive -NoProfile $myInvocation.MyCommand
    }#End If
    $ExitResult=$LASTEXITCODE

    If ($Null -ne ([System.Management.Automation.PSTypeName]'Kernel32.Wow64').Type -and $Null -ne [Kernel32.Wow64].GetMethod('Wow64DisableWow64FsRedirection') -and $FSRedirectionDisabled -eq $True) {
        [ref]$defaultptr = New-Object System.IntPtr
        $Result = [Kernel32.Wow64]::Wow64RevertWow64FsRedirection($defaultptr)
        Write-Verbose 'System32 path redirection has been re-enabled.'
    }#End If
    Write-Warning 'Exiting 64-bit session. Module will only remain loaded in native 64-bit PowerShell environment.'
    Exit $ExitResult
}#End If

#Ignore SSL errors
If ($Null -eq ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
    Add-Type -Debug:$False @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
}
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
#Enable TLS, TLS1.1, TLS1.2, TLS1.3 in this session if they are available
IF([Net.SecurityProtocolType]::Tls) {[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls}
IF([Net.SecurityProtocolType]::Tls11) {[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls11}
IF([Net.SecurityProtocolType]::Tls12) {[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12}
IF([Net.SecurityProtocolType]::Tls13) {[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13}

#region [Functions]-------------------------------------------------------------

Function Get-LTServiceInfo{
<#
.SYNOPSIS
    This function will pull all of the registry data into an object.

.NOTES
    Version:        1.5
    Author:         Chris Taylor
    Website:        labtechconsulting.com
    Creation Date:  3/14/2016
    Purpose/Change: Initial script development

    Update Date: 6/1/2017
    Purpose/Change: Updates for better overall compatibility, including better support for PowerShell V2

    Update Date: 8/24/2017
    Purpose/Change: Update to use Clear-Variable.

    Update Date: 3/12/2018
    Purpose/Change: Support for ShouldProcess to enable -Confirm and -WhatIf.

    Update Date: 8/28/2018
    Purpose/Change: Remove '~' from server addresses.

    Update Date: 1/19/2019
    Purpose/Change: Improved BasePath value assignment

.LINK
    http://labtechconsulting.com
#>
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Low')]
    Param ()

    Begin{
        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)"
        Clear-Variable key,BasePath,exclude,Servers -EA 0 -WhatIf:$False -Confirm:$False #Clearing Variables for use
        $exclude = "PSParentPath","PSChildName","PSDrive","PSProvider","PSPath"
        $key = $Null
    }#End Begin

    Process{
        If ((Test-Path 'HKLM:\SOFTWARE\LabTech\Service') -eq $False){
            Write-Error "ERROR: Line $(LINENUM): Unable to find information on LTSvc. Make sure the agent is installed."
            Return $Null
        }#End If

        If ($PSCmdlet.ShouldProcess("LTService", "Retrieving Service Registry Values")) {
            Write-Verbose "Checking for LT Service registry keys."
            Try{
                $key = Get-ItemProperty 'HKLM:\SOFTWARE\LabTech\Service' -ErrorAction Stop | Select-Object * -exclude $exclude
                If ($Null -ne $key -and -not ($key|Get-Member -EA 0|Where-Object {$_.Name -match 'BasePath'})) {
                    If ((Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LTService') -eq $True) {
                        Try {
                            $BasePath = Get-Item $( Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LTService' -ErrorAction Stop|Select-Object -Expand ImagePath | Select-String -Pattern '^[^"][^ ]+|(?<=^")[^"]+'|Select-Object -Expand Matches -First 1 | Select-Object -Expand Value -EA 0 -First 1 ) | Select-Object -Expand DirectoryName -EA 0
                        } Catch {
                            $BasePath = "${env:windir}\LTSVC"
                        }#End Try
                    } Else {
                        $BasePath = "${env:windir}\LTSVC"
                    }#End If
                    Add-Member -InputObject $key -MemberType NoteProperty -Name BasePath -Value $BasePath
                }#End If
                $key.BasePath = [System.Environment]::ExpandEnvironmentVariables($($key|Select-Object -Expand BasePath -EA 0)) -replace '\\\\','\'
                If ($Null -ne $key -and ($key|Get-Member|Where-Object {$_.Name -match 'Server Address'})) {
                    $Servers = ($Key|Select-Object -Expand 'Server Address' -EA 0).Split('|')|ForEach-Object {$_.Trim() -replace '~',''}|Where-Object {$_ -match '.+'}
                    Add-Member -InputObject $key -MemberType NoteProperty -Name 'Server' -Value $Servers -Force
                }#End If
            }#End Try

            Catch{
                Write-Error "ERROR: Line $(LINENUM): There was a problem reading the registry keys. $($Error[0])"
            }#End Catch
        }#End If
    }#End Process

    End{
        If ($?){
            Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)"
            return $key
        } Else {
            Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)"
        }#End If
    }#End End
}#End Function Get-LTServiceInfo

Function Get-LTServiceSettings{
<#
.SYNOPSIS
    This function will pull the registry data from HKLM:\SOFTWARE\LabTech\Service\Settings into an object.

.NOTES
    Version:        1.1
    Author:         Chris Taylor
    Website:        labtechconsulting.com
    Creation Date:  3/14/2016
    Purpose/Change: Initial script development

    Update Date: 6/1/2017
    Purpose/Change: Updates for better overall compatibility, including better support for PowerShell V2

.LINK
    http://labtechconsulting.com
#>
    [CmdletBinding()]
    Param ()

    Begin{
        Write-Verbose "Checking for registry keys."
        if ((Test-Path 'HKLM:\SOFTWARE\LabTech\Service\Settings') -eq $False){
            Write-Error "ERROR: Unable to find LTSvc settings. Make sure the agent is installed."
        }
        $exclude = "PSParentPath","PSChildName","PSDrive","PSProvider","PSPath"
    }#End Begin

    Process{
        Try{
            Get-ItemProperty HKLM:\SOFTWARE\LabTech\Service\Settings -ErrorAction Stop | Select-Object * -exclude $exclude
        }#End Try

        Catch{
            Write-Error "ERROR: There was a problem reading the registry keys. $($Error[0])"
        }#End Catch
    }#End Process

    End{
        if ($?){
            $key
        }
    }#End End
}#End Function Get-LTServiceSettings

Function Restart-LTService{
<#
.SYNOPSIS
    This function will restart the LabTech Services.

.NOTES
    Version:        1.3
    Author:         Chris Taylor
    Website:        labtechconsulting.com
    Creation Date:  3/14/2016
    Purpose/Change: Initial script development

    Update Date: 6/1/2017
    Purpose/Change: Updates for better overall compatibility, including better support for PowerShell V2

    Update Date: 3/13/2018
    Purpose/Change: Added additional debugging output, support for ShouldProcess (-Confirm, -WhatIf)

    Update Date: 3/21/2018
    Purpose/Change: Removed ErrorAction Override

.LINK
    http://labtechconsulting.com
#>
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param()

    Begin{
        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)"
    }#End Begin

    Process{
        if (-not (Get-Service 'LTService','LTSvcMon' -ErrorAction SilentlyContinue)) {
            If ($WhatIfPreference -ne $True) {
                Write-Error "ERROR: Line $(LINENUM): Services NOT Found $($Error[0])"
                return
            } Else {
                Write-Error "What-If: Line $(LINENUM): Stopping: Services NOT Found"
                return
            }#End If
        }#End IF
        Try{
            Stop-LTService
        }#End Try
        Catch{
            Write-Error "ERROR: Line $(LINENUM): There was an error stopping the services. $($Error[0])"
            return
        }#End Catch

        Try{
            Start-LTService
        }#End Try
        Catch{
            Write-Error "ERROR: Line $(LINENUM): There was an error starting the services. $($Error[0])"
            return
        }#End Catch
    }#End Process

    End{
        If ($WhatIfPreference -ne $True) {
            If ($?) {Write-Output "Services Restarted successfully."}
            Else {$Error[0]}
        }#End If
        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)"
    }#End End
}#End Function Restart-LTService

Function Stop-LTService{
<#
.SYNOPSIS
    This function will stop the LabTech Services.

.DESCRIPTION
    This function will verify that the LabTech services are present then attempt to stop them.
    It will then check for any remaining LabTech processes and kill them.

.NOTES
    Version:        1.3
    Author:         Chris Taylor
    Website:        labtechconsulting.com
    Creation Date:  3/14/2016
    Purpose/Change: Initial script development

    Update Date: 6/1/2017
    Purpose/Change: Updates for better overall compatibility, including better support for PowerShell V2

    Update Date: 3/12/2018
    Purpose/Change: Updated Support for ShouldProcess to enable -Confirm and -WhatIf parameters.

    Update Date: 3/21/2018
    Purpose/Change: Removed ErrorAction Override

.LINK
    http://labtechconsulting.com
#>
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param()

    Begin{
        Clear-Variable sw,timeout,svcRun -EA 0 -WhatIf:$False -Confirm:$False -Verbose:$False #Clearing Variables for use
        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)"
    }#End Begin

    Process{
        if (-not (Get-Service 'LTService','LTSvcMon' -ErrorAction SilentlyContinue)) {
            If ($WhatIfPreference -ne $True) {
                Write-Error "ERROR: Line $(LINENUM): Services NOT Found $($Error[0])"
                return
            } Else {
                Write-Error "What If: Line $(LINENUM): Stopping: Services NOT Found"
                return
            }#End If
        }#End If
        If ($PSCmdlet.ShouldProcess("LTService, LTSvcMon", "Stop-Service")) {
            $Null=Invoke-LTServiceCommand ('Kill VNC','Kill Trays') -EA 0 -WhatIf:$False -Confirm:$False
            Write-Verbose "Stopping Labtech Services"
            Try{
                ('LTService','LTSvcMon') | Foreach-Object {
                    Try {$Null=& "${env:windir}\system32\sc.exe" stop "$($_)" 2>''}
                    Catch {Write-Output "Error calling sc.exe."}
                }
                $timeout = new-timespan -Minutes 1
                $sw = [diagnostics.stopwatch]::StartNew()
                Write-Host -NoNewline "Waiting for Services to Stop."
                Do {
                    Write-Host -NoNewline '.'
                    Start-Sleep 2
                    $svcRun = ('LTService','LTSvcMon') | Get-Service -EA 0 | Where-Object {$_.Status -ne 'Stopped'} | Measure-Object | Select-Object -Expand Count
                } Until ($sw.elapsed -gt $timeout -or $svcRun -eq 0)
                Write-Host ""
                $sw.Stop()
                if ($svcRun -gt 0) {
                    Write-Verbose "Services did not stop. Terminating Processes after $(([int32]$sw.Elapsed.TotalSeconds).ToString()) seconds."
                }
                Get-Process | Where-Object {@('LTTray','LTSVC','LTSvcMon') -contains $_.ProcessName } | Stop-Process -Force -ErrorAction Stop -Whatif:$False -Confirm:$False
            }#End Try

