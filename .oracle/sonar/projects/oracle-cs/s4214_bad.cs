public class NativeClipboard
{
    [DllImport("user32.dll")]
    public static extern int OpenClipboard(int owner);

    [DllImport("user32.dll")]
    protected static extern int GetClipboardData(int format);

    [DllImport("user32.dll")]
    protected internal static extern int CloseClipboard();
}
