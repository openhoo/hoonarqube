public class Sample
{
    public bool Check(string name, string title)
    {
        bool missing = string.IsNullOrEmpty(name);
        bool filled = name != null && name != "";
        bool mismatched = name == null || title == "";
        return missing || filled || mismatched;
    }
}
