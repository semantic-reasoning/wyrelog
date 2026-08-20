param(
  [Parameter(Mandatory = $true)]
  [string] $Command
)

Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class WyrelogTokenPrivileges
{
    private const UInt32 TOKEN_QUERY = 0x0008;
    private const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
    private const UInt32 ERROR_NOT_ALL_ASSIGNED = 1300;

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public UInt32 LowPart;
        public Int32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public UInt32 PrivilegeCount;
        public Luid Luid;
        public UInt32 Attributes;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        UInt32 desiredAccess,
        out IntPtr tokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupPrivilegeValue(
        string systemName,
        string privilegeName,
        out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle,
        bool disableAllPrivileges,
        ref TokenPrivileges newState,
        UInt32 bufferLength,
        IntPtr previousState,
        IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static bool TryEnable(string privilegeName)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, out token))
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "OpenProcessToken failed");

        try
        {
            Luid luid;
            if (!LookupPrivilegeValue(null, privilegeName, out luid))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "LookupPrivilegeValue failed");

            TokenPrivileges privileges = new TokenPrivileges {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = SE_PRIVILEGE_ENABLED
            };
            if (!AdjustTokenPrivileges(token, false, ref privileges, 0,
                    IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "AdjustTokenPrivileges failed");

            int error = Marshal.GetLastWin32Error();
            if (error == ERROR_NOT_ALL_ASSIGNED)
                return false;
            if (error != 0)
                throw new Win32Exception(error,
                    "AdjustTokenPrivileges did not enable the requested privilege");
            return true;
        }
        finally
        {
            CloseHandle(token);
        }
    }
}
'@

$privilege_enabled =
    [WyrelogTokenPrivileges]::TryEnable('SeCreateSymbolicLinkPrivilege')
if ($privilege_enabled) {
  Write-Host 'SeCreateSymbolicLinkPrivilege enabled for the Windows test process.'
} else {
  # GitHub-hosted Windows images run as administrators but do not assign
  # SeCreateSymbolicLinkPrivilege to that logon.  Developer Mode is the
  # documented unprivileged CreateSymbolicLinkW path and is effective for the
  # child test process without requiring a new logon token.
  $developer_mode_key =
      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock'
  try {
    New-Item -Path $developer_mode_key -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $developer_mode_key `
        -Name AllowDevelopmentWithoutDevLicense -PropertyType DWord -Value 1 `
        -Force -ErrorAction Stop | Out-Null
    Write-Host 'Developer Mode enabled for unprivileged Windows symlink tests.'
  } catch {
    Write-Warning ('Developer Mode could not be enabled; continuing with the '
      + 'current token capability: ' + $_.Exception.Message)
  }
}

$temporary_path = [System.IO.Path]::GetTempFileName()
$batch_path = [System.IO.Path]::ChangeExtension($temporary_path, '.cmd')
try {
  $batch_content = "@echo off`r`ncd /d `"$env:GITHUB_WORKSPACE`"`r`n$Command"
  Set-Content -Path $batch_path -Value $batch_content -Encoding ASCII
  & $env:ComSpec /D /E:ON /V:OFF /C $batch_path
  $command_exit_code = $LASTEXITCODE
} finally {
  Remove-Item -LiteralPath $batch_path -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $temporary_path -Force -ErrorAction SilentlyContinue
}
if ($command_exit_code -ne 0) {
  exit $command_exit_code
}
