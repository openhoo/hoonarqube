public class Sample
{
    public int Pick(bool flag, int value)
    {
        int adjusted = flag ? value : -value;
        string label = adjusted >= 0 ? "ok" : "low";
        return adjusted + label.Length;
    }
}
