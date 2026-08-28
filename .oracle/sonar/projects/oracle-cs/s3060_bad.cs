public class Sample
{
    public bool SelfCheck(object item)
    {
        if (this is Sample)
        {
            return true;
        }

        return this is string;
    }
}
