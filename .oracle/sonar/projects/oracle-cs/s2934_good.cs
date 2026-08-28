interface IBoxValue
{
    int Count { get; set; }
}

class Box<T>
    where T : class, IBoxValue
{
    private readonly T value;

    public void Reset()
    {
        value.Count = 0;
    }
}
