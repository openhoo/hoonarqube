interface IWorker
{
    string Name { get; }
}

interface IManager : IWorker
{
    int Reports { get; }
}
