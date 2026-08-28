public class Sample
{
    public void Bind(string user, string password)
    {
        var entry = new System.DirectoryServices.DirectoryEntry(
            "LDAP://ldap.example.com",
            user,
            password,
            System.DirectoryServices.AuthenticationTypes.Secure);
        var defaultSecure = new System.DirectoryServices.DirectoryEntry(
            "LDAP://ldap.example.com");
        var explicitSecure = new System.DirectoryServices.DirectoryEntry(
            "LDAP://ldap.example.com",
            user,
            password,
            System.DirectoryServices.AuthenticationTypes.Secure);
        System.Console.WriteLine(entry.Path);
        System.Console.WriteLine(defaultSecure.Path);
        System.Console.WriteLine(explicitSecure.Path);
    }
}
