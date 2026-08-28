using System;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Permissions;

[assembly: AllowPartiallyTrustedCallers]

[Serializable]
public class SafeWidget : ISerializable
{
    [FileIOPermission(SecurityAction.Demand, Unrestricted = true)]
    public SafeWidget()
    {
    }

    [FileIOPermission(SecurityAction.Demand, Unrestricted = true)]
    protected SafeWidget(SerializationInfo info, StreamingContext context)
    {
    }

    void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context)
    {
    }
}
