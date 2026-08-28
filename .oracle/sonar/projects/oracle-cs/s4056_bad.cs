public class S4056Bad
{
    public string Text(int value)
    {
        return value.ToString();
    }

    public int Number(string text)
    {
        return int.Parse(text);
    }
}
