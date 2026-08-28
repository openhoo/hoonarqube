public class Sample
{
    public sealed class Box
    {
        public int Value { get; set; }
    }

    public Box Build()
    {
        return new Box() { Value = 42 };
    }
}
