interface IShape
{
    double Area();
}

class Square : IShape
{
    public double Area()
    {
        return 1.0;
    }
}

class Canvas
{
    public double Measure(IShape shape)
    {
        var square = (Square)shape;
        return square.Area();
    }
}
