using System;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Permissions;

[assembly: AllowPartiallyTrustedCallers]

[Serializable]
public class Widget : ISerializable
{
    [FileIOPermission(SecurityAction.Demand, Unrestricted = true)]
    public Widget()
    {
    }

    protected Widget(SerializationInfo info, StreamingContext context) // S4212
    {
    }

    void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context)
    {
    }
}
