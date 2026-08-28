using System.Xml;

public class Sample
{
    public void Decode(string xml)
    {
        var parser = new XmlDocument();
        parser.XmlResolver = new XmlUrlResolver(); // S2755
        parser.LoadXml(xml);
    }
}
