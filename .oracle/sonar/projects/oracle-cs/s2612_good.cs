using System.Security.AccessControl;

public class Writer
{
    public void Apply()
    {
        var safeRule = new FileSystemAccessRule(
            "Everyone",
            FileSystemRights.FullControl,
            AccessControlType.Deny);
        var security = new FileSecurity();
        security.AddAccessRule(safeRule);
    }
}
