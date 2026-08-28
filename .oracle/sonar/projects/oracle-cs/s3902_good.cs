public class Probe
{
    public void Who(System.Type knownType)
    {
        Keep(knownType.Assembly);
    }

    private static void Keep(System.Reflection.Assembly assembly)
    {
    }
}
