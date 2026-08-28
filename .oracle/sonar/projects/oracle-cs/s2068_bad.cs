public class S2068Bad
{
    public void Connect()
    {
        string password = "Admin123";
        string usernamePassword = "user=admin;password=Admin123";
        Login(password, usernamePassword);
    }

    private void Login(string password, string usernamePassword) { }
}
