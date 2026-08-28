public class Inventory
{
    private int units;

    public int GetUnits()
    {
        return units;
    }

    public string DisplayName { get; set; }

    public void AddUnits(int count)
    {
        units += count;
    }
}
