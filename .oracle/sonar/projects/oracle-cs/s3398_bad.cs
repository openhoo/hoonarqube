class Outer
{
    private static void Shared()
    {
    }

    class Inner
    {
        void Run()
        {
            Shared();
        }
    }
}
