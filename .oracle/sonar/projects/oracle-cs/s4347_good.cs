class Simulator
{
    public int Next(int seed)
    {
        var rng = new Random(seed);
        return rng.Next();
    }
}
