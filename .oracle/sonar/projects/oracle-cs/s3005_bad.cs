using System.Text;

public class Context
{
    [ThreadStatic]
    private static StringBuilder Buffer;

    [ThreadStatic]
    private StringBuilder scratch;
}
