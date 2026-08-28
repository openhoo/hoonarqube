public class NativeResource
{
    public void Leak(System.Runtime.InteropServices.SafeHandle firstSafeHandle)
    {
        Use(firstSafeHandle.DangerousGetHandle());
    }

    public void Steal(System.Runtime.InteropServices.SafeHandle secondSafeHandle)
    {
        Use(secondSafeHandle.DangerousGetHandle());
    }

    private static void Use(System.IntPtr handle)
    {
    }
}
