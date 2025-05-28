using namespace System.Text
using namespace System.Runtime.InteropServices

#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Launches a process with TrustedInstaller privileges.
.DESCRIPTION
    This script provides functionality to start a process as NT AUTHORITY\SYSTEM
    by impersonating the TrustedInstaller service. The script must be run with
    administrator privileges.
.EXAMPLE
    PS C:\> .\RunAsTI.ps1 -Executable "cmd.exe" -Arguments "/c whoami /all > C:\temp\ti_whoami.txt" -Verbose
    This example launches cmd.exe as TrustedInstaller and redirects its output.

.PARAMETER Executable
    The full path to the executable to launch.
.PARAMETER Arguments
    The command-line arguments for the executable.
.PARAMETER ShowWindow
    How the window for the new process should be shown. Defaults to 'SW_SHOWNORMAL'.
    Possible values: SW_HIDE, SW_SHOWNORMAL, SW_NORMAL, SW_SHOWMINIMIZED, SW_SHOWMAXIMIZED,
    SW_MAXIMIZE, SW_SHOWNOACTIVATE, SW_SHOW, SW_MINIMIZE, SW_SHOWMINNOACTIVE,
    SW_SHOWNA, SW_RESTORE, SW_SHOWDEFAULT.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Executable = "cmd.exe",

    [Parameter(Mandatory = $false)]
    [string]$Arguments,

    [Parameter(Mandatory = $false)]
    [ShowWindowType]$ShowWindow = [ShowWindowType]::SW_SHOWNORMAL # FIX: Explicitly set enum default here
)

#region Native Methods, Structs, Enums via Add-Type
$CSharPTypeDef = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

// Replicates VB6 ShowWindowType enum values
public enum ShowWindowType : ushort
{
    SW_HIDE = 0,
    SW_SHOWNORMAL = 1,
    SW_NORMAL = 1,
    SW_SHOWMINIMIZED = 2,
    SW_SHOWMAXIMIZED = 3,
    SW_MAXIMIZE = 3,
    SW_SHOWNOACTIVATE = 4,
    SW_SHOW = 5,
    SW_MINIMIZE = 6,
    SW_SHOWMINNOACTIVE = 7,
    SW_SHOWNA = 8,
    SW_RESTORE = 9,
    SW_SHOWDEFAULT = 10
}

// Replicates VB6 STARTUP_FLAGS enum values
[Flags]
public enum STARTUP_FLAGS : uint
{
    STARTF_USESHOWWINDOW = 0x00000001,
    STARTF_USESIZE = 0x00000002,
    STARTF_USEPOSITION = 0x00000004,
    STARTF_USECOUNTCHARS = 0x00000008,
    STARTF_USEFILLATTRIBUTE = 0x00000010,
    STARTF_RUNFULLSCREEN = 0x00000020,
    STARTF_FORCEONFEEDBACK = 0x00000040,
    STARTF_FORCEOFFFEEDBACK = 0x00000080,
    STARTF_USESTDHANDLES = 0x00000100,
    STARTF_USEHOTKEY = 0x00000200,
    STARTF_TITLEISLINKNAME = 0x00000800,
    STARTF_TITLEISAPPID = 0x00001000,
    STARTF_PREVENTPINNING = 0x00002000,
    STARTF_UNTRUSTEDSOURCE = 0x00008000
}

// Replicates VB6 SE_PRIVILEGE_ATTRIBUTES
[Flags]
public enum SE_PRIVILEGE_ATTRIBUTES : uint
{
    SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
    SE_PRIVILEGE_ENABLED = 0x00000002,
    SE_PRIVILEGE_REMOVED = 0x00000004,
    SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000
}

// Replicates VB6 TOKEN_TYPE
public enum TOKEN_TYPE
{
    TokenPrimary = 1,
    TokenImpersonation
}

// Replicates VB6 SECURITY_IMPERSONATION_LEVEL
public enum SECURITY_IMPERSONATION_LEVEL
{
    SecurityAnonymous = 0,
    SecurityIdentification = 1,
    SecurityImpersonation = 2,
    SecurityDelegation = 3
}

// Replicates VB6 ServiceState
public enum ServiceState : uint
{
    SERVICE_STOPPED = 0x00000001,
    SERVICE_START_PENDING = 0x00000002,
    SERVICE_STOP_PENDING = 0x00000003,
    SERVICE_RUNNING = 0x00000004,
    SERVICE_CONTINUE_PENDING = 0x00000005,
    SERVICE_PAUSE_PENDING = 0x00000006,
    SERVICE_PAUSED = 0x00000007,
    SERVICE_NO_CHANGE = 0xFFFFFFFF
}

// Replicates VB6 ServiceType (partial, only used one)
[Flags]
public enum ServiceType : uint
{
    SERVICE_KERNEL_DRIVER = 0x00000001,
    SERVICE_FILE_SYSTEM_DRIVER = 0x00000002,
    SERVICE_WIN32_OWN_PROCESS = 0x00000010,
    SERVICE_WIN32_SHARE_PROCESS = 0x00000020,
    SERVICE_INTERACTIVE_PROCESS = 0x00000100
    // SERVICETYPE_NO_CHANGE would be SERVICE_NO_CHANGE from ServiceState
}
// Replicates VB6 ServiceControlAccepted (partial, only used one)
[Flags]
public enum ServiceControlAccepted : uint
{
    SERVICE_ACCEPT_STOP = 0x00000001,
    SERVICE_ACCEPT_PAUSE_CONTINUE = 0x00000002,
    SERVICE_ACCEPT_SHUTDOWN = 0x00000004
    // ... and others
}

// Replicates VB6 ServiceControlManagerType
[Flags]
public enum ServiceControlManagerType : uint
{
    SC_MANAGER_CONNECT = 0x0001,
    SC_MANAGER_CREATE_SERVICE = 0x0002,
    SC_MANAGER_ENUMERATE_SERVICE = 0x0004,
    SC_MANAGER_LOCK = 0x0008,
    SC_MANAGER_QUERY_LOCK_STATUS = 0x0010,
    SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020,
    SC_MANAGER_ALL_ACCESS = 0xF003F // STANDARD_RIGHTS_REQUIRED | SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_LOCK | SC_MANAGER_QUERY_LOCK_STATUS | SC_MANAGER_MODIFY_BOOT_CONFIG
}

// Replicates VB6 ACCESS_TYPE (for services)
[Flags]
public enum ServiceAccessType : uint
{
    SERVICE_QUERY_CONFIG = 0x0001,
    SERVICE_CHANGE_CONFIG = 0x0002,
    SERVICE_QUERY_STATUS = 0x0004,
    SERVICE_ENUMERATE_DEPENDENTS = 0x0008,
    SERVICE_START = 0x0010,
    SERVICE_STOP = 0x0020,
    SERVICE_PAUSE_CONTINUE = 0x0040,
    SERVICE_INTERROGATE = 0x0080,
    SERVICE_USER_DEFINED_CONTROL = 0x0100,
    SERVICE_ALL_ACCESS = 0xF01FF // STANDARD_RIGHTS_REQUIRED | SERVICE_QUERY_CONFIG | ...
}

// Replicates VB6 TH32CS_Flags
[Flags]
public enum TH32CS_Flags : uint
{
    TH32CS_SNAPHEAPLIST = 0x00000001,
    TH32CS_SNAPPROCESS = 0x00000002,
    TH32CS_SNAPTHREAD = 0x00000004,
    TH32CS_SNAPMODULE = 0x00000008,
    TH32CS_SNAPALL = TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE,
    TH32CS_INHERIT = 0x80000000
}

[StructLayout(LayoutKind.Sequential)]
public struct LUID
{
    public uint LowPart;
    public int HighPart;
}

[StructLayout(LayoutKind.Sequential)]
public struct LUID_AND_ATTRIBUTES
{
    public LUID Luid;
    public SE_PRIVILEGE_ATTRIBUTES Attributes;
}

// Sized for 1 privilege, as commonly used
[StructLayout(LayoutKind.Sequential)]
public struct TOKEN_PRIVILEGES
{
    public uint PrivilegeCount;
    public LUID_AND_ATTRIBUTES Privileges; // Only one, for simplicity of this common case
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFOW
{
    public uint cbSize;
    public string lpReserved;
    public IntPtr lpDesktop; // LPWSTR
    public string lpTitle;
    public uint dwX;
    public uint dwY;
    public uint dwXSize;
    public uint dwYSize;
    public uint dwXCountChars;
    public uint dwYCountChars;
    public uint dwFillAttribute;
    public STARTUP_FLAGS dwFlags;
    public ShowWindowType wShowWindow;
    public ushort cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public uint dwProcessId;
    public uint dwThreadId;
}

[StructLayout(LayoutKind.Sequential)]
public struct SERVICE_STATUS_PROCESS
{
    public ServiceType dwServiceType;
    public ServiceState dwCurrentState;
    public ServiceControlAccepted dwControlsAccepted;
    public uint dwWin32ExitCode;
    public uint dwServiceSpecificExitCode;
    public uint dwCheckPoint;
    public uint dwWaitHint;
    public uint dwProcessId;
    public uint dwServiceFlags;
}

[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES
{
    public int nLength;
    public IntPtr lpSecurityDescriptor;
    public bool bInheritHandle;
}

[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_QUALITY_OF_SERVICE
{
    public uint Length;
    public SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    public byte ContextTrackingMode; // SECURITY_CONTEXT_TRACKING_MODE
    public byte EffectiveOnly;
}


[StructLayout(LayoutKind.Sequential)]
public struct THREADENTRY32
{
    public uint dwSize;
    public uint cntUsage;
    public uint th32ThreadID;
    public uint th32OwnerProcessID;
    public int tpBasePri; // LONG
    public int tpDeltaPri; // LONG
    public uint dwFlags;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)] // szExeFile is ANSI in original
public struct PROCESSENTRY32
{
    public uint dwSize;
    public uint cntUsage;
    public uint th32ProcessID;
    public IntPtr th32DefaultHeapID; // ULONG_PTR
    public uint th32ModuleID;
    public uint cntThreads;
    public uint th32ParentProcessID;
    public int pcPriClassBase; // LONG
    public uint dwFlags;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string szExeFile;
}


public static class NativeConstants
{
    public const string SE_DEBUG_NAME = "SeDebugPrivilege";
    public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";

    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_DUPLICATE = 0x0002;
    public const uint TOKEN_IMPERSONATE = 0x0004;
    public const uint TOKEN_QUERY_SOURCE = 0x0010;
    public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    public const uint TOKEN_ADJUST_GROUPS = 0x0040;
    public const uint TOKEN_ADJUST_DEFAULT = 0x0080;
    public const uint TOKEN_ALL_ACCESS = (0x000F0000 | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT); // STANDARD_RIGHTS_REQUIRED
    public const uint MAXIMUM_ALLOWED = 0x02000000;

    public const uint THREAD_DIRECT_IMPERSONATION = 0x0200;
    public const uint PROCESS_DUP_HANDLE = 0x0040;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400; // Or PROCESS_QUERY_LIMITED_INFORMATION 0x1000

    public const uint ERROR_SERVICE_ALREADY_RUNNING = 0x420; // 1056
    public const uint STATUS_SUCCESS = 0x00000000;
    public const uint LOGON_WITH_PROFILE = 0x00000001;
    public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

    public const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
    public const uint FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
    public const uint FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;

    public const int SC_STATUS_PROCESS_INFO = 0;
}

public static class NativeMethods
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        uint dwLogonFlags,
        [MarshalAs(UnmanagedType.LPWStr)] string lpApplicationName,
        [MarshalAs(UnmanagedType.LPWStr)] string lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        [MarshalAs(UnmanagedType.LPWStr)] string lpCurrentDirectory,
        ref STARTUPINFOW lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern void Sleep(uint dwMilliseconds);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint BufferLength,
        IntPtr PreviousState, // Using IntPtr for optional out
        IntPtr ReturnLength); // Using IntPtr for optional out

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValueW(
        string lpSystemName,
        string lpName,
        out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenSCManagerW(
        string lpMachineName,
        string lpDatabaseName,
        ServiceControlManagerType dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenServiceW(
        IntPtr hSCManager,
        string lpServiceName,
        ServiceAccessType dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool StartServiceW(
        IntPtr hService,
        uint dwNumServiceArgs,
        IntPtr lpServiceArgVectors);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(TH32CS_Flags dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
    
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern uint NtImpersonateThread(IntPtr ThreadHandle, IntPtr ThreadToImpersonate, ref SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr phToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        ref SECURITY_ATTRIBUTES lpTokenAttributes,
        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        TOKEN_TYPE TokenType,
        out IntPtr phNewToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true, CharSet=CharSet.Ansi)] // Process32First/Next use PROCESSENTRY32 with ANSI szExeFile
    public static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet=CharSet.Ansi)]
    public static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf(); // Added for robustness

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool QueryServiceStatusEx(
        IntPtr hService,
        int InfoLevel, // SC_STATUS_PROCESS_INFO
        out SERVICE_STATUS_PROCESS lpBuffer,
        uint cbBufSize,
        out uint pcbBytesNeeded);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint FormatMessageW(
        uint dwFlags,
        IntPtr lpSource,
        uint dwMessageId,
        uint dwLanguageId,
        StringBuilder lpBuffer,
        uint nSize,
        IntPtr Arguments);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibraryW(string lpLibFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr hModule);
    
    [DllImport("shlwapi.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr PathGetArgsW(string pszPath);

    [DllImport("shlwapi.dll", CharSet = CharSet.Unicode)]
    public static extern void PathRemoveArgsW(StringBuilder pszPath);
    
    [DllImport("ole32.dll")]
    public static extern void CoTaskMemFree(IntPtr pv);
}
"@
Add-Type -TypeDefinition $CSharPTypeDef
#endregion Native Methods, Structs, Enums via Add-Type


class RunAsTI {
    hidden [IntPtr]$tiTokenHandle = [IntPtr]::Zero
    hidden [bool]$isInitialized = $false
    hidden [IntPtr]$ntDllHandle = [IntPtr]::Zero

    RunAsTI() {
        # Constructor - Load ntdll.dll for GetNtStatusName if needed
        $this.ntDllHandle = [NativeMethods]::LoadLibraryW("ntdll.dll")
    }

    [void] Dispose() {
        $this.ReleaseToken()
        # Ensure the current thread reverts to its original security context if it was impersonating.
        if (-not [NativeMethods]::RevertToSelf()) {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "Dispose::Failed to revert to self. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
        }
        if ($this.ntDllHandle -ne [IntPtr]::Zero) {
            [NativeMethods]::FreeLibrary($this.ntDllHandle)
            $this.ntDllHandle = [IntPtr]::Zero
        }
    }

    hidden [string] GetWin32ErrorName([int]$errorCode) {
        $sb = New-Object System.Text.StringBuilder(1024)
        $len = [NativeMethods]::FormatMessageW(
            [NativeConstants]::FORMAT_MESSAGE_FROM_SYSTEM -bor [NativeConstants]::FORMAT_MESSAGE_IGNORE_INSERTS,
            [IntPtr]::Zero,
            [uint32]$errorCode,
            0, # Auto language
            $sb,
            $sb.Capacity,
            [IntPtr]::Zero
        )
        if ($len -gt 0) {
            return $sb.ToString(0, $len).Trim()
        }
        return "Unknown error code 0x$($errorCode.ToString('X'))"
    }
    
    hidden [string] GetNtStatusName([uint32]$ntStatus) {
        if ($this.ntDllHandle -eq [IntPtr]::Zero) {
            return "NTSTATUS 0x$($ntStatus.ToString('X')) (ntdll.dll not loaded for FormatMessage)"
        }
        $sb = New-Object System.Text.StringBuilder(1024)
        $len = [NativeMethods]::FormatMessageW(
            [NativeConstants]::FORMAT_MESSAGE_FROM_HMODULE -bor [NativeConstants]::FORMAT_MESSAGE_IGNORE_INSERTS,
            $this.ntDllHandle,
            $ntStatus,
            0, # Auto language
            $sb,
            $sb.Capacity,
            [IntPtr]::Zero
        )
        if ($len -gt 0) {
            return $sb.ToString(0, $len).Trim()
        }
        return "Unknown NTSTATUS code 0x$($ntStatus.ToString('X'))"
    }


    hidden [bool] SetPrivilege([IntPtr]$tokenHandle, [string]$privilegeName, [bool]$enablePrivilege) {
        Write-Verbose "SetPrivilege: Setting '$privilegeName' to $($enablePrivilege)"
        $luid = New-Object LUID
        if (-not [NativeMethods]::LookupPrivilegeValueW($null, $privilegeName, ([ref]$luid))) {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "SetPrivilege::LookupPrivilegeValueW for '$privilegeName' failed. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
            return $false
        }

        $tp = New-Object TOKEN_PRIVILEGES
        $tp.PrivilegeCount = 1
        $tp.Privileges.Luid = $luid
        # FIX: Use [SE_PRIVILEGE_ATTRIBUTES]0 for disabled, as SE_PRIVILEGE_NONE is not an enum member
        $tp.Privileges.Attributes = if ($enablePrivilege) { [SE_PRIVILEGE_ATTRIBUTES]::SE_PRIVILEGE_ENABLED } else { [SE_PRIVILEGE_ATTRIBUTES]0 }

        # FIX: Pass the instance $tp to SizeOf, not the type [TOKEN_PRIVILEGES]
        if (-not [NativeMethods]::AdjustTokenPrivileges($tokenHandle, $false, ([ref]$tp), [System.Runtime.InteropServices.Marshal]::SizeOf($tp), [IntPtr]::Zero, [IntPtr]::Zero)) {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "SetPrivilege::AdjustTokenPrivileges for '$privilegeName' failed. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
            return $false
        }
        
        $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($lastError -eq 0) { # ERROR_SUCCESS
            Write-Verbose "SetPrivilege for '$privilegeName' succeeded."
            return $true
        } elseif ($lastError -eq 1300) { # ERROR_NOT_ALL_ASSIGNED
            Write-Warning "SetPrivilege for '$privilegeName': Not all privileges assigned. This may be okay if the privilege was already set."
            return $true # Treat as success for this purpose
        } else {
            Write-Warning "SetPrivilege for '$privilegeName' AdjustTokenPrivileges returned an unexpected error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
            return $false
        }
    }

    hidden [void] AdjustPrivileges() {
        $processTokenHandle = [IntPtr]::Zero
        if (-not [NativeMethods]::OpenProcessToken([NativeMethods]::GetCurrentProcess(), ([NativeConstants]::TOKEN_ADJUST_PRIVILEGES -bor [NativeConstants]::TOKEN_QUERY), ([ref]$processTokenHandle))) {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "AdjustPrivileges::Failed to open process token. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
            return
        }
        Write-Verbose "AdjustPrivileges::Got process token."

        if ($this.SetPrivilege($processTokenHandle, [NativeConstants]::SE_DEBUG_NAME, $true)) {
            Write-Verbose "AdjustPrivileges::Enabled debug privilege."
        } else {
            Write-Warning "AdjustPrivileges::Failed to enable debug privilege."
        }

        if ($this.SetPrivilege($processTokenHandle, [NativeConstants]::SE_IMPERSONATE_NAME, $true)) {
            Write-Verbose "AdjustPrivileges::Enabled impersonate privilege."
        } else {
            Write-Warning "AdjustPrivileges::Failed to enable impersonate privilege."
        }

        [NativeMethods]::CloseHandle($processTokenHandle) | Out-Null
    }

    hidden [uint32] FindProcessByName([string]$processName) {
        $snapshotHandle = [NativeMethods]::CreateToolhelp32Snapshot([TH32CS_Flags]::TH32CS_SNAPPROCESS, 0)
        if ($snapshotHandle -eq [IntPtr]::MinusOne -or $snapshotHandle -eq [IntPtr]::Zero) { # INVALID_HANDLE_VALUE is -1
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "FindProcessByName::CreateToolhelp32Snapshot failed. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
            return 0
        }

        $pe32 = New-Object PROCESSENTRY32
        $pe32.dwSize = [System.Runtime.InteropServices.Marshal]::SizeOf($pe32)

        if ([NativeMethods]::Process32First($snapshotHandle, ([ref]$pe32))) {
            do {
                if ($pe32.szExeFile -eq $processName) {
                    [NativeMethods]::CloseHandle($snapshotHandle) | Out-Null
                    Write-Verbose "FindProcessByName: Found '$processName' with PID $($pe32.th32ProcessID)."
                    return $pe32.th32ProcessID
                }
            } while ([NativeMethods]::Process32Next($snapshotHandle, ([ref]$pe32)))
        } else {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "FindProcessByName::Process32First failed. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
        }
        [NativeMethods]::CloseHandle($snapshotHandle) | Out-Null
        Write-Warning "FindProcessByName: Process '$processName' not found."
        return 0
    }
    
    # Removed ImpersonateSystem, as it's not strictly necessary for this approach and may cause issues.
    # The required privileges (SeDebugPrivilege, SeImpersonatePrivilege) are enabled in AdjustPrivileges().

    hidden [uint32] GetFirstThreadId([uint32]$processId) {
        $snapshotHandle = [NativeMethods]::CreateToolhelp32Snapshot([TH32CS_Flags]::TH32CS_SNAPTHREAD, 0)
        if ($snapshotHandle -eq [IntPtr]::MinusOne -or $snapshotHandle -eq [IntPtr]::Zero) {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "GetFirstThreadId::CreateToolhelp32Snapshot failed. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
            return 0
        }

        $te32 = New-Object THREADENTRY32
        $te32.dwSize = [System.Runtime.InteropServices.Marshal]::SizeOf($te32)

        if ([NativeMethods]::Thread32First($snapshotHandle, ([ref]$te32))) {
            do {
                if ($te32.th32OwnerProcessID -eq $processId) {
                    [NativeMethods]::CloseHandle($snapshotHandle) | Out-Null
                    Write-Verbose "GetFirstThreadId: Found thread ID $($te32.th32ThreadID) for PID $processId."
                    return $te32.th32ThreadID
                }
            } while ([NativeMethods]::Thread32Next($snapshotHandle, ([ref]$te32)))
        } else {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "GetFirstThreadId::Thread32First failed. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
        }
        [NativeMethods]::CloseHandle($snapshotHandle) | Out-Null
        Write-Warning "GetFirstThreadId: No thread found for PID $processId."
        return 0
    }

    # New helper function to acquire token once PID is known
    hidden [bool] AcquireTiTokenFromPid([uint32]$tiPid) {
        $tiTid = $this.GetFirstThreadId($tiPid)
        Write-Verbose "AcquireTiTokenFromPid::First thread ID for PID $tiPid is $tiTid."
        if ($tiTid -eq 0) {
            Write-Warning "AcquireTiTokenFromPid::Failed to get TrustedInstaller thread ID."
            return $false
        }

        $threadHandle = [NativeMethods]::OpenThread([NativeConstants]::THREAD_DIRECT_IMPERSONATION, $false, $tiTid)
        if ($threadHandle -eq [IntPtr]::Zero) {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "AcquireTiTokenFromPid::Failed to open TrustedInstaller thread. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
            return $false
        }
        Write-Verbose "AcquireTiTokenFromPid::TrustedInstaller thread opened. Impersonating..."

        $sqos = New-Object SECURITY_QUALITY_OF_SERVICE
        $sqos.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($sqos)
        $sqos.ImpersonationLevel = [SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation
        # ContextTrackingMode and EffectiveOnly are 0 (byte default)

        $ntStatus = [NativeMethods]::NtImpersonateThread([NativeMethods]::GetCurrentThread(), $threadHandle, ([ref]$sqos))
        [NativeMethods]::CloseHandle($threadHandle) | Out-Null # Close TI thread handle regardless of impersonation result

        if ($ntStatus -ne [NativeConstants]::STATUS_SUCCESS) {
            Write-Warning "AcquireTiTokenFromPid::NtImpersonateThread failed. NTSTATUS: $($this.GetNtStatusName($ntStatus)) (0x$($ntStatus.ToString('X')))"
            return $false
        }
        Write-Verbose "AcquireTiTokenFromPid::NtImpersonateThread STATUS_SUCCESS. Opening current thread token..."
        
        $currentThreadToken = [IntPtr]::Zero
        if (-not [NativeMethods]::OpenThreadToken([NativeMethods]::GetCurrentThread(), [NativeConstants]::TOKEN_ALL_ACCESS, $false, ([ref]$currentThreadToken))) {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "AcquireTiTokenFromPid::Failed to open own thread token after NtImpersonateThread. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
        } else {
            Write-Verbose "AcquireTiTokenFromPid::OpenThreadToken success. TI Token acquired."
            $this.tiTokenHandle = $currentThreadToken # Store the acquired token
        }
        
        # Revert impersonation immediately after getting the token
        if (-not [NativeMethods]::RevertToSelf()) {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "AcquireTiTokenFromPid::Failed to revert to self after acquiring TI token. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
        } else {
            Write-Verbose "AcquireTiTokenFromPid::Successfully reverted to self."
        }
        
        return ($this.tiTokenHandle -ne [IntPtr]::Zero)
    }

    hidden [bool] StartAndAcquireTiToken() {
        $tiPid = 0
        
        # FIRST ATTEMPT: Try to find TrustedInstaller if it's already running
        Write-Verbose "StartAndAcquireTiToken::Attempting to find running TrustedInstaller process..."
        $tiPid = $this.FindProcessByName("TrustedInstaller.exe")
        if ($tiPid -ne 0) {
            Write-Verbose "StartAndAcquireTiToken::Found existing TrustedInstaller PID: $tiPid."
            # Acquire token from the found PID
            return $this.AcquireTiTokenFromPid($tiPid)
        }

        # If TrustedInstaller.exe is not found running, proceed to start the service
        Write-Verbose "StartAndAcquireTiToken::TrustedInstaller not found running. Attempting to start service via SCM..."
        $scManagerHandle = [NativeMethods]::OpenSCManagerW($null, $null, [ServiceControlManagerType]::SC_MANAGER_ALL_ACCESS)
        if ($scManagerHandle -eq [IntPtr]::Zero) {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "StartAndAcquireTiToken::Failed to open SCManager. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
            return $false
        }
        Write-Verbose "StartAndAcquireTiToken::Service manager opened. Opening TrustedInstaller service..."

        $serviceHandle = [NativeMethods]::OpenServiceW($scManagerHandle, "TrustedInstaller", ([ServiceAccessType]::SERVICE_START -bor [ServiceAccessType]::SERVICE_QUERY_STATUS))
        if ($serviceHandle -eq [IntPtr]::Zero) {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "StartAndAcquireTiToken::Failed to open TrustedInstaller service. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
            [NativeMethods]::CloseHandle($scManagerHandle) | Out-Null
            return $false
        }
        Write-Verbose "StartAndAcquireTiToken::Attempting to start TrustedInstaller service..."

        $serviceStatusProcess = New-Object SERVICE_STATUS_PROCESS
        $bytesNeeded = 0
        $maxAttempts = 10 
        $attempt = 0

        while($attempt -lt $maxAttempts) {
            $attempt++
            if (-not [NativeMethods]::QueryServiceStatusEx($serviceHandle, [NativeConstants]::SC_STATUS_PROCESS_INFO, ([ref]$serviceStatusProcess), [System.Runtime.InteropServices.Marshal]::SizeOf($serviceStatusProcess), ([ref]$bytesNeeded))) {
                $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "StartAndAcquireTiToken::QueryServiceStatusEx failed. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
                break
            }

            if ($serviceStatusProcess.dwCurrentState -eq [ServiceState]::SERVICE_STOPPED) {
                Write-Verbose "StartAndAcquireTiToken::Service currently stopped, starting..."
                if (-not [NativeMethods]::StartServiceW($serviceHandle, 0, [IntPtr]::Zero)) {
                    $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if ($lastError -ne [NativeConstants]::ERROR_SERVICE_ALREADY_RUNNING) {
                        Write-Warning "StartAndAcquireTiToken::Error starting TrustedInstaller service. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
                        break 
                    } else {
                        Write-Verbose "StartAndAcquireTiToken::StartServiceW reported already running, proceeding to check status."
                    }
                }
                [NativeMethods]::Sleep(100) 
            } elseif (($serviceStatusProcess.dwCurrentState -eq [ServiceState]::SERVICE_START_PENDING) -or ($serviceStatusProcess.dwCurrentState -eq [ServiceState]::SERVICE_STOP_PENDING)) {
                $waitHint = if ($serviceStatusProcess.dwWaitHint -eq 0) { 250 } else { $serviceStatusProcess.dwWaitHint }
                Write-Verbose "StartAndAcquireTiToken::Service state is $($serviceStatusProcess.dwCurrentState), waiting $($waitHint)ms."
                [NativeMethods]::Sleep($waitHint)
            } elseif ($serviceStatusProcess.dwCurrentState -eq [ServiceState]::SERVICE_RUNNING) {
                Write-Verbose "StartAndAcquireTiToken::Service running, PID: $($serviceStatusProcess.dwProcessId)."
                $tiPid = $serviceStatusProcess.dwProcessId
                break 
            } else {
                Write-Warning "StartAndAcquireTiToken::Service in unexpected state: $($serviceStatusProcess.dwCurrentState)."
                [NativeMethods]::Sleep(500)
            }
        } 

        [NativeMethods]::CloseHandle($serviceHandle) | Out-Null
        [NativeMethods]::CloseHandle($scManagerHandle) | Out-Null
        
        if ($tiPid -ne 0) {
            # Now that we have the PID (either found or started), acquire the token
            return $this.AcquireTiTokenFromPid($tiPid)
        } else {
            Write-Warning "StartAndAcquireTiToken::Failed to get TrustedInstaller PID or service did not transition to running state."
            return $false
        }
    }

    [bool] Launch([string]$executablePath, [string]$arguments, [ShowWindowType]$showWindowVal) {
        if (-not $this.isInitialized) {
            Write-Verbose "Launch::First run. Enabling privileges..."
            $this.AdjustPrivileges()
            # Removed $this.ImpersonateSystem() - it's often not strictly necessary and may cause issues.
            # The script should rely on SeDebugPrivilege and SeImpersonatePrivilege.
            $this.isInitialized = $true
        }

        if ($this.tiTokenHandle -eq [IntPtr]::Zero) {
            Write-Verbose "Launch::TI token not acquired yet. Attempting to start service and acquire token..."
            if (-not $this.StartAndAcquireTiToken()) {
                Write-Error "Launch::Failed to acquire TrustedInstaller token."
                # StartAndAcquireTiToken now handles its own RevertToSelf.
                return $false
            }
        }

        if ($this.tiTokenHandle -eq [IntPtr]::Zero) {
            Write-Error "Launch::Token hijack failed. TI Token is still null."
            return $false
        }
        Write-Verbose "Launch::Duplicating stolen TI token..."

        $secAttrs = New-Object SECURITY_ATTRIBUTES
        $secAttrs.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($secAttrs)

        $duplicatedTokenHandle = [IntPtr]::Zero
        if (-not [NativeMethods]::DuplicateTokenEx(
                $this.tiTokenHandle,
                [NativeConstants]::MAXIMUM_ALLOWED, # Or TOKEN_ALL_ACCESS
                ([ref]$secAttrs),
                [SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation, # Or SecurityDelegation if needed for child processes
                [TOKEN_TYPE]::TokenPrimary, # Create a primary token
                ([ref]$duplicatedTokenHandle))) {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "Launch::Failed to duplicate TI token. Error: $($this.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
            return $false
        }
        Write-Verbose "Launch::Token duplicated. Creating process..."

        $startupInfo = New-Object STARTUPINFOW
        $startupInfo.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($startupInfo)
        $desktopName = "WinSta0\Default"
        $startupInfo.lpDesktop = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($desktopName)
        $startupInfo.dwFlags = [STARTUP_FLAGS]::STARTF_USESHOWWINDOW
        $startupInfo.wShowWindow = $showWindowVal

        $processInfo = New-Object PROCESS_INFORMATION

        $fullCommandLine = if ([string]::IsNullOrEmpty($arguments)) { $executablePath } else { "$($executablePath) $($arguments)" }
        
        $success = [NativeMethods]::CreateProcessWithTokenW(
            $duplicatedTokenHandle,
            [NativeConstants]::LOGON_WITH_PROFILE,
            $executablePath, # lpApplicationName
            $fullCommandLine, # lpCommandLine
            [NativeConstants]::CREATE_UNICODE_ENVIRONMENT, # dwCreationFlags
            [IntPtr]::Zero, # lpEnvironment
            $null, # lpCurrentDirectory (inherits from caller)
            ([ref]$startupInfo),
            ([ref]$processInfo)
        )
        
        $lastErrorCreateProcess = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

        # Clean up allocated memory for lpDesktop
        if ($startupInfo.lpDesktop -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($startupInfo.lpDesktop)
        }
        # Clean up duplicated token
        if ($duplicatedTokenHandle -ne [IntPtr]::Zero) {
            [NativeMethods]::CloseHandle($duplicatedTokenHandle) | Out-Null
        }
        # Close process and thread handles from PROCESS_INFORMATION if process created successfully
        if ($success) {
            if ($processInfo.hProcess -ne [IntPtr]::Zero) {[NativeMethods]::CloseHandle($processInfo.hProcess) | Out-Null}
            if ($processInfo.hThread -ne [IntPtr]::Zero) {[NativeMethods]::CloseHandle($processInfo.hThread) | Out-Null}
        }


        if (-not $success) {
            Write-Error "Launch::CreateProcessWithTokenW failed. Error: $($this.GetWin32ErrorName($lastErrorCreateProcess)) (0x$($lastErrorCreateProcess.ToString('X')))"
            return $false
        }

        Write-Verbose "Launch::Process created successfully. PID: $($processInfo.dwProcessId)"
        
        return $true
    }

    [void] ReleaseToken() {
        if ($this.tiTokenHandle -ne [IntPtr]::Zero) {
            Write-Verbose "ReleaseToken::Closing TI token handle."
            [NativeMethods]::CloseHandle($this.tiTokenHandle) | Out-Null
            $this.tiTokenHandle = [IntPtr]::Zero
        }
    }
}

# --- Main script execution ---
$global:RunAsTiInstance = $null # Ensure it's cleared if script is dot-sourced multiple times

try {
    $global:RunAsTiInstance = [RunAsTI]::new()
    
    # The param's type is ShowWindowType already, so a direct assignment is sufficient.
    $showWindowValue = $ShowWindow 

    if ($global:RunAsTiInstance.Launch($Executable, $Arguments, $showWindowValue)) {
        Write-Host "Process '$Executable' launched successfully as TrustedInstaller."
    } else {
        Write-Error "Failed to launch process '$Executable' as TrustedInstaller."
        # Consider exiting with a non-zero code
        # exit 1 
    }
}
catch {
    Write-Error "An unexpected error occurred: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
}
finally {
    if ($global:RunAsTiInstance -is [IDisposable]) {
        $global:RunAsTiInstance.Dispose()
    } elseif ($global:RunAsTiInstance -ne $null) { # Basic cleanup if not full IDisposable
        $global:RunAsTiInstance.ReleaseToken()
        if ($global:RunAsTiInstance.ntDllHandle -ne [IntPtr]::Zero) {
            [NativeMethods]::FreeLibrary($global:RunAsTiInstance.ntDllHandle) | Out-Null
            $global:RunAsTiInstance.ntDllHandle = [IntPtr]::Zero
        }
        # Final safety check to revert impersonation
        if (-not [NativeMethods]::RevertToSelf()) {
            $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "Finally::Failed to revert to self. Error: $($global:RunAsTiInstance.GetWin32ErrorName($lastError)) (0x$($lastError.ToString('X')))"
        }
    }
}