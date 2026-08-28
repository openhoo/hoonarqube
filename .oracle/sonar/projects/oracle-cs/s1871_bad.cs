public class Sample
{
    public int Pick(int n)
    {
        switch (n)
        {
            case 1:
                n += 10;
                n += 20;
                return n;
            case 2:
                n += 10;
                n += 20;
                return n;
            default:
                return 0;
        }
    }
}
