using System.Xml;
using System.Xml.Linq;

public class Greeter
{
    public string Describe(System.Xml.Linq.XElement element)
    {
        return element.ToString();
    }
}
