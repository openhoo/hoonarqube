class Registry
{
    private static int Limit = 10;

    class Mirror
    {
        private static int Limit = 5;

        static int Read()
        {
            return Limit;
        }
    }
}
