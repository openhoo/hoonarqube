[System.ComponentModel.Composition.Export(typeof(IProcessor))]
public class Processor : IProcessor
{
    public void Run()
    {
    }
}

[System.ComponentModel.Composition.Export("processor")]
public class NamedProcessor
{
}

public interface IProcessor
{
    void Run();
}
