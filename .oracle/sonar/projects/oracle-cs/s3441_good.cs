public class Sample
{
    public object Build(string city, string zip)
    {
        return new
        {
            City = city,
            Zip = zip,
            TownName = city,
            ZipCode = zip
        };
    }
}
