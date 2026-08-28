public class First
{
    private readonly int id;

    public override bool Equals(object obj)
    {
        return obj is First other && id == other.id;
    }
}

public class Second
{
    public override int GetHashCode()
    {
        return 42;
    }
}
