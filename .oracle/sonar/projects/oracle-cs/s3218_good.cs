class Registry
{
    private static int Limit = 10;

    class Mirror
    {
        private static int Cap = 5;

        static int Read()
        {
            return Cap;
        }
    }
}
