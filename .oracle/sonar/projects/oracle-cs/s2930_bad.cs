class Importer
{
    public void Load()
    {
        FileStream first = new FileStream("a", FileMode.Open);
        StreamReader second = new StreamReader("b");
    }
}
