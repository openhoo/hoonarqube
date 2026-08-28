class ShippingCalculator
{
    public decimal Rate(int zones)
    {
        return zones * 42 + 0.25m;
    }

    public double Weight()
    {
        return 2.5e2;
    }
}
