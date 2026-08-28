using System.Text;

public class Context
{
    [ThreadStatic]
    private static StringBuilder Buffer;

    [ThreadStatic]
    private static int Depth;

    private static StringBuilder plain = new StringBuilder();
}
