public class GateFilter
{
    public bool All(bool a, bool b, bool c, bool d, bool e)
    {
        return a && b && c && d && e;
    }

    public bool Any(bool a, bool b, bool c, bool d, bool e)
    {
        return a || b || c || d || e;
    }
}
