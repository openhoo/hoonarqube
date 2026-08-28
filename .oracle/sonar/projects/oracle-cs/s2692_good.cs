public class Sample
{
    public bool Find(string text)
    {
        if (text.IndexOf('a') >= 0)
        {
            return true;
        }

        if (text.IndexOf('b') > 1)
        {
            return false;
        }

        return text.Contains("z");
    }
}
