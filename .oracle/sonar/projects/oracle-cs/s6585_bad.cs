public class Formatters
{
    public string Long(System.DateTime value)
    {
        return value.ToString("yyyy-MM-dd HH:mm:ss");
    }

    public string Short(System.DateTime value)
    {
        return value.ToString("dd/MM/yyyy");
    }
}
