public class S4058Bad
{
    public int Order(string left, string right)
    {
        return string.Compare(left, right);
    }

    public bool Same(string left, string right)
    {
        return string.Equals(left, right);
    }
}
