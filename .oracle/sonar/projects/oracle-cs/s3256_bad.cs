public class Sample
{
    public bool Check(string name)
    {
        return "".Equals(name) || !name.Equals("") || name.Equals(string.Empty);
    }
}
