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

    public static void Enable(string privilegeName)
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
                throw new Win32Exception(error,
                    "The runner token does not hold the requested privilege");
            if (error != 0)
                throw new Win32Exception(error,
                    "AdjustTokenPrivileges did not enable the requested privilege");
        }
        finally
        {
            CloseHandle(token);
        }
    }
}
'@

[WyrelogTokenPrivileges]::Enable('SeCreateSymbolicLinkPrivilege')
Write-Host 'SeCreateSymbolicLinkPrivilege enabled for the Windows test process.'

& $env:ComSpec /D /E:ON /V:OFF /S /C $Command
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}
