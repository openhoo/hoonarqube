internal class NativeAudio
{
    [DllImport("winmm.dll")]
    private static extern int PlaySound(string name, int module, int flags);

    [DllImport("winmm.dll")]
    internal static extern int WaveOutGetVolume(int device, out int volume);

    public static bool Chime(string name)
    {
        return PlaySound(name, 0, 0) != 0;
    }
}
