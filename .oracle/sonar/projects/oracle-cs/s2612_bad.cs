using System.Security.AccessControl;

public class Writer
{
    public void Apply()
    {
        var unsafeRule = new FileSystemAccessRule(
            "Everyone",
            FileSystemRights.FullControl,
            AccessControlType.Allow);
        var security = new FileSecurity();
        security.AddAccessRule(unsafeRule);
        security.SetAccessRule(unsafeRule);
        security.ResetAccessRule(unsafeRule);
    }
}
