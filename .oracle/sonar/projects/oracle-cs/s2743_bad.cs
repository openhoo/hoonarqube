using System.Collections.Generic;

public class Registry<T>
{
    private static readonly Dictionary<string, T> Items = new Dictionary<string, T>();

    private static int Count;
}
