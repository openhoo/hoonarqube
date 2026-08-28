public class TableReader
{
    private int[][] rows = new int[4][];

    public string[] Headers { get; set; }

    public int Total(int[][] grid)
    {
        return grid.Length;
    }
}
