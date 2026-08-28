using System.Xml;

public class Sample
{
    public void Decode(string xml)
    {
        var parser = new XmlDocument();
        parser.XmlResolver = null;
        parser.LoadXml(xml);
    }
}
