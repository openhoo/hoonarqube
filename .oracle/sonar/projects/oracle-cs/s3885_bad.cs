public class Loader
{
    public void Fetch(string path, string name)
    {
        System.Reflection.Assembly.LoadFrom(path);
        System.Reflection.Assembly.LoadWithPartialName(name);
    }
}
