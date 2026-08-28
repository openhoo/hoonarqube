[SuppressMessage("Performance", "CA1804:Remove unused locals", Justification = "legacy")]
public class Patcher
{
    public void Apply()
    {
#pragma warning disable CS0618
        Legacy();
    }

    private static void Legacy()
    {
    }
}
