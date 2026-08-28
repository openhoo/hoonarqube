class Users
{
    void Store(byte[] password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        int iterations = 100000;
        var derive = new Rfc2898DeriveBytes(password, salt, iterations);
        var bytes = derive.GetBytes(32);
    }
}
