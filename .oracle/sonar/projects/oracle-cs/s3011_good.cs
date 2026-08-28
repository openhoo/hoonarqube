public class Probe
{
    public void Inspect(System.Type type)
    {
        type.GetMethod("Visible", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);
        type.GetProperty("Name");
    }
}
