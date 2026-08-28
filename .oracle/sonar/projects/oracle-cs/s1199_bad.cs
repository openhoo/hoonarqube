public class ScopeProbe
{
    public void Run()
    {
        int total = 0;
        {
            total += 1;
        }
        Use(total);
    }

    private static void Use(int value)
    {
    }
}
