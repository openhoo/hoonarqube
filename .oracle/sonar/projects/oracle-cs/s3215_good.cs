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
    public double Measure(Square square)
    {
        var shape = (IShape)square;
        return shape.Area();
    }
}
