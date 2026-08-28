interface IGreeter
{
    void Greet();
}

class BaseGreeter : IGreeter
{
    public void Greet()
    {
    }
}

class DerivedGreeter : BaseGreeter
{
    public void Run()
    {
        Greet();
    }
}
