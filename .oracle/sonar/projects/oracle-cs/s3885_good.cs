public class Loader
{
    public System.Reflection.Assembly Fetch(string name)
    {
        return System.Reflection.Assembly.Load(name);
    }
}
