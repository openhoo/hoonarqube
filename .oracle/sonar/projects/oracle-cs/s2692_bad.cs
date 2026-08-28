public class Sample
{
    public bool Find(string text)
    {
        if (text.IndexOf('a') > 0)
        {
            return true;
        }

        return 0 > text.LastIndexOf("key");
    }
}
