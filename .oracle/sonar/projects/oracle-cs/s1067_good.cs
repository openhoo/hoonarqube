public class GateFilter
{
    public bool All(bool a, bool b, bool c, bool d)
    {
        return a && b && c && d;
    }

    public bool Mixed(bool a, bool b, bool c, bool d)
    {
        return (a && b) || (c && d);
    }
}
