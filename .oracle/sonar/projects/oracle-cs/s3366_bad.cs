class Widget
{
    public Widget()
    {
        System.Console.WriteLine(this);
        Register(this);
    }

    void Register(Widget other)
    {
    }
}
