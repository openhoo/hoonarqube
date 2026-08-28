public class GridHolder
{
    private int[,] cells = new int[3, 4];

    public string[,] Names { get; set; }

    public decimal[,] Weights()
    {
        return new decimal[2, 2];
    }

    public int Sum(int[,] values)
    {
        return values.Length;
    }
}
