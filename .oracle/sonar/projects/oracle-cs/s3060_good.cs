public class Sample
{
    public bool OtherCheck(object item)
    {
        if (item is Sample)
        {
            return true;
        }

        return item is string;
    }
}
