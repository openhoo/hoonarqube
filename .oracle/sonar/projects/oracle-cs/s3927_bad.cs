using System.Runtime.Serialization;

public class Widget
{
    [OnSerializing]
    public void WrongParameter(int value)
    {
    }

    [OnDeserialized]
    internal void ExtraParameter(StreamingContext context, string tag)
    {
    }

    [OnSerialized]
    public int NonVoidCallback(StreamingContext context) => 0;
}
