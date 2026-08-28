using System.Text;

public class Context
{
    [ThreadStatic]
    private static StringBuilder Buffer = new StringBuilder();

    [ThreadStatic]
    private static int Depth;
}
