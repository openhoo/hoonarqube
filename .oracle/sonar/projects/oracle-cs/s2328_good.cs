public class Stamp
{
    private int moving;
    private readonly int frozen;

    public override int GetHashCode()
    {
        return frozen * 31;
    }

    public void Advance()
    {
        moving = moving + 1;
    }
}
