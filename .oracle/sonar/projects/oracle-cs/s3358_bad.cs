public class Sample
{
    public int Pick(bool flag, int value)
    {
        return flag ? value > 0 ? 1 : 0 : -1;
    }

    public string Label(int score)
    {
        return score > 50 ? "high" : score > 20 ? "mid" : "low";
    }
}
