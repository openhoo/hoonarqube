public interface IWorker
{
    string Name { get; }
}

public interface IManager
{
    string Name { get; }
}

public interface ILead : IWorker, IManager
{
}
