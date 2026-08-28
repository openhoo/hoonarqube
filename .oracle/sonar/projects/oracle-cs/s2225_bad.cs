public class BrokenLabel
{
    public override string ToString() => null;
}

public class BrokenSummary
{
    public override string ToString()
    {
        if (IsEmpty())
        {
            return null;
        }
        return Name();
    }

    private bool IsEmpty()
    {
        return true;
    }

    private string Name()
    {
        return "summary";
    }
}
