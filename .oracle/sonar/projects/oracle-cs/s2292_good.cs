public class TemperatureScale
{
    private double celsius;

    public double Fahrenheit
    {
        get { return celsius * 9.0 / 5.0 + 32.0; }
        set { celsius = (value - 32.0) * 5.0 / 9.0; }
    }
}
