public class Probe
{
    public void Inspect(System.Type type)
    {
        type.GetMethod("Secret", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        type.GetField("hidden", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
    }
}
