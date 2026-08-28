using System.Runtime.Serialization;

public class SafeWidget
{
    [OnSerializing]
    private void BeforeSerialize(StreamingContext context)
    {
    }

    [OnDeserialized]
    private void AfterDeserialize(StreamingContext context)
    {
    }

    [OnSerialized]
    private void AfterSerialize(StreamingContext context)
    {
    }

    [OnDeserializing]
    private void BeforeDeserialize(StreamingContext context)
    {
    }

    private void PlainHelper(int value)
    {
    }
}
