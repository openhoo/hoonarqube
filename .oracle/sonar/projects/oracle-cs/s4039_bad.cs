public interface IGreeter
{
    void Greet();
}

public class BaseGreeter : IGreeter
{
    void IGreeter.Greet()
    {
        Greet();
    }
}
