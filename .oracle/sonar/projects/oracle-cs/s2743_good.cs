using System.Collections.Generic;

public class Registry<T>
{
    private readonly List<T> items = new List<T>();

    private int count;
}

public class RegistryMetrics
{
    private static int Hits;
}
