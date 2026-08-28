public class Sample
{
    public int Bucket(int value)
    {
        switch (value)
        {
            case 1:
                return 10;
            default:
                return 0;
            case 2:
                return 20;
        }
    }
}
