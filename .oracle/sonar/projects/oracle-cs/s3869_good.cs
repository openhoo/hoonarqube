public class NativeResource
{
    public void Hold(System.Runtime.InteropServices.SafeHandle safeHandle)
    {
        Keep(safeHandle);
    }

    private static void Keep(System.Runtime.InteropServices.SafeHandle safeHandle)
    {
    }
}
