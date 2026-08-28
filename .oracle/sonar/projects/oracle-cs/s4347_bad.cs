class Simulator
{
    public int Next()
    {
        var rng = new Random(12345);
        return rng.Next();
    }
}
