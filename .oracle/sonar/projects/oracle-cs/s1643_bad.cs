public class ReportBuilder
{
    public string Build(string[] lines)
    {
        var text = "";
        foreach (var line in lines)
        {
            text += line;
            text += "\n";
        }
        return text;
    }
}
