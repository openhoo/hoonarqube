public class Sample
{
    public int Bucket(int value)
    {
        var result = 0;
        switch (value)
        {
            case 1:
                result = 1;
                break;
            default:
                result = -1;
                break;
        }
        return result;
    }
}
