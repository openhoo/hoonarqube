class Importer
{
    public void Load()
    {
        using var stream = new FileStream("a", FileMode.Open);
    }
}
