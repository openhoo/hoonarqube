class Loader
{
    public void Load(System.Uri value)
    {
        System.Console.WriteLine(value);
    }

    public void Load(string text)
    {
        Load(new System.Uri(text));
    }
}
