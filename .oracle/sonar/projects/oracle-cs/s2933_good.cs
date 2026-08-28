class Meter
{
    private int stamp;

    public void Reset()
    {
        stamp = 1;
    }

    public int Value
    {
        get { return stamp; }
    }
}
