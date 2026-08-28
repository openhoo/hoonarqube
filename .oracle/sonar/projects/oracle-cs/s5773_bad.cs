using Newtonsoft.Json;

public class Sample
{
    public object Loop(string json)
    {
        var settings = new JsonSerializerSettings();
        settings.TypeNameHandling = TypeNameHandling.Objects;
        var mode = Newtonsoft.Json.TypeNameHandling.Arrays;
        settings.TypeNameHandling = TypeNameHandling.Auto;
        return JsonConvert.DeserializeObject(json, typeof(object), settings) ?? mode;
    }
}
