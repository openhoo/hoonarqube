[System.ComponentModel.Composition.Export(typeof(IProcessor))]
public class Processor
{
}

public interface IProcessor
{
    void Run();
}
