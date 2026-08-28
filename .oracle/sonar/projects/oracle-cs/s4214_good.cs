internal class NativeClipboard
{
    [DllImport("user32.dll")]
    private static extern int OpenClipboard(int owner);

    [DllImport("user32.dll")]
    internal static extern int CloseClipboard();

    public bool TryOpen(int owner)
    {
        return OpenClipboard(owner) != 0;
    }
}
