using System;
using System.Runtime.InteropServices;

public class ComBootstrapper
{
    [DllImport("ole32.dll")]
    private static extern int CoSetProxyBlanket(
        [MarshalAs(UnmanagedType.IUnknown)] object? proxy,
        uint authenticationService,
        uint authorizationService,
        [MarshalAs(UnmanagedType.LPWStr)] string? serverPrincipalName,
        uint authenticationLevel,
        uint impersonationLevel,
        IntPtr authenticationInfo,
        uint capabilities);

    [DllImport("ole32.dll")]
    private static extern int CoInitializeSecurity(
        IntPtr securityDescriptor,
        int authenticationServiceCount,
        IntPtr authenticationServices,
        IntPtr reserved,
        uint authenticationLevel,
        uint impersonationLevel,
        IntPtr authenticationList,
        uint capabilities,
        IntPtr reservedAgain);

    public void Boot()
    {
        _ = CoSetProxyBlanket(null, 0, 0, null, 0, 0, IntPtr.Zero, 0); // S3884
        _ = CoInitializeSecurity(IntPtr.Zero, -1, IntPtr.Zero, IntPtr.Zero, 1, 3, IntPtr.Zero, 0, IntPtr.Zero); // S3884
    }
}
