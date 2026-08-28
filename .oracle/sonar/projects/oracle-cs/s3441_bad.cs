public class Sample
{
    public string City { get; set; }

    public string Zip { get; set; }

    public object Build()
    {
        return new
        {
            City = City,
            Zip = Zip
        };
    }
}
