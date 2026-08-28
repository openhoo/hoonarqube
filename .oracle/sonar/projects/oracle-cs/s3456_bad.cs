public class CharWalker
{
    public char First(string text)
    {
        return text.ToArray()[0];
    }

    public int CountBangs(string text)
    {
        var total = 0;
        foreach (char c in text.ToCharArray())
        {
            if (c == '!')
            {
                total = total + 1;
            }
        }
        return total;
    }
}
