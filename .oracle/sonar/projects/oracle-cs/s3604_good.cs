public class Sample
{
    public sealed class Box
    {
        public int Width { get; set; }
        public int Height { get; set; }
    }

    public Box Build(int width)
    {
        var box = new Box() { Width = width, Height = width * 2 };
        return box;
    }
}
