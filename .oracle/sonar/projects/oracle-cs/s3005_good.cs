using System.Text;

public class Context
{
    [ThreadStatic]
    private static StringBuilder Buffer;

    private StringBuilder scratch;
}
