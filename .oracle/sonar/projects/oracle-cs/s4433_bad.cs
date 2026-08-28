public class Sample
{
    public void Bind()
    {
        var entry = new System.DirectoryServices.DirectoryEntry(
            "LDAP://ldap.example.com",
            null,
            null,
            System.DirectoryServices.AuthenticationTypes.Anonymous);
        System.Console.WriteLine(entry.Path);
    }
}
