using Newtonsoft.Json;

public class Sample
{
    private enum Options
    {
        None,
        All,
        Auto,
    }

    public JsonSerializerSettings Tight()
    {
        return new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.None,
        };
    }

    public void OtherEnums()
    {
        var opts = Options.All;
        var style = System.Runtime.Serialization.Formatters.FormatterAssemblyStyle.Simple;
        _ = opts + " " + style;
    }
}
