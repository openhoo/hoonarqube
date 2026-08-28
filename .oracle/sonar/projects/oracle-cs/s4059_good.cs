public class Account
{
    public string Name { get; set; }

    public decimal Balance { get; set; }

    public string RenderName()
    {
        return Name;
    }

    public string GetHolder()
    {
        return "holder";
    }
}
