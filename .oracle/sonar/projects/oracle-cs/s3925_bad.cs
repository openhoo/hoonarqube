public class Session : System.Runtime.Serialization.ISerializable
{
    public void GetObjectData(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
    {
        info.AddValue("user", "someone");
    }
}
