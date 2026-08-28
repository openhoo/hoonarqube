public class Sample
{
    public bool Check(object item)
    {
        bool exact = item.GetType() == typeof(string);
        bool inverted = typeof(int) != item.GetType();
        return exact && inverted;
    }
}
