public class Wrapper
{
    private readonly string id;

    public bool SameAs(Wrapper other)
    {
        return id == other.id;
    }
}
