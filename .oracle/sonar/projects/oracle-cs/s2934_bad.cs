interface IBoxValue
{
    int Count { get; set; }
    string Name { get; set; }
}

class Box<T> where T : IBoxValue
{
    private readonly T value;

    public void Reset()
    {
        value.Count = 0;
        value.Name = "x";
    }
}
