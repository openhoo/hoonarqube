enum ShippingMode
{
    Express = 3,
}

class ShippingCalculator
{
    private const int MaxZones = 12;

    public decimal Rate(int zones, decimal fallback = 9.95m)
    {
        if (zones > MaxZones)
        {
            return fallback;
        }

        return zones * MaxZones;
    }
}
