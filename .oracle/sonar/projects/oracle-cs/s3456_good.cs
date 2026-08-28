public class CharWalker
{
    public char First(string text)
    {
        var chars = text.ToArray();
        return chars[0];
    }

    public int CountBangs(string text)
    {
        var total = 0;
        foreach (char c in text)
        {
            if (c == '!')
            {
                total = total + 1;
            }
        }
        return total;
    }

    private static void Use(char[] again)
    {
    }
}
