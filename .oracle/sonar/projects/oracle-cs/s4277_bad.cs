[System.ComponentModel.Composition.Shared]
public class Cache
{
}

[System.ComponentModel.Composition.PartCreationPolicy(System.ComponentModel.Composition.CreationPolicy.Shared)]
public class Registry
{
}

public class Consumer
{
    public void Load()
    {
        var cache = new Cache();
        var registry = new Registry();
        System.Console.WriteLine(cache);
        System.Console.WriteLine(registry);
    }
}
