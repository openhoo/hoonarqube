public class S4040Bad
{
    public string Key(string name)
    {
        return name.Trim().ToLower();
    }

    public string Slug(string raw)
    {
        return raw.ToLowerInvariant().Replace(" ", "-");
    }
}
