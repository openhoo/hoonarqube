public class Inventory
{
    private int units;

    public int getUnits()
    {
        return units;
    }

    public string displayName { get; set; }

    public void addUnits(int count)
    {
        units += count;
    }
}
