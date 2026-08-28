public class Consumer
{
    public void Load(System.ComponentModel.Composition.Hosting.CompositionContainer container)
    {
        var cache = container.GetExportedValue<Cache>();
        var settings = new Settings();
        System.Console.WriteLine(cache);
        System.Console.WriteLine(settings);
    }
}

public class Cache
{
}

public class Settings
{
}
