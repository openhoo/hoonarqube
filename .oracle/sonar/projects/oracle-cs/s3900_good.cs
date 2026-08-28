class Validator
{
    public int Length(string? text)
    {
        if (text == null)
        {
            return 0;
        }
        return text.Length;
    }
}
