internal class NativeAudio
{
    [DllImport("winmm.dll")]
    private static extern int PlaySound(string name, int module, int flags);

    public int Probe() => 0;

    public static bool Chime(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("A sound name is required.", nameof(name));
        }

        return PlaySound(name, 0, 0) != 0;
    }
}
