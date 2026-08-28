public class Pair
{
    private readonly int id;

    public override bool Equals(object obj)
    {
        return obj is Pair other && id == other.id;
    }

    public override int GetHashCode()
    {
        return id.GetHashCode();
    }
}
