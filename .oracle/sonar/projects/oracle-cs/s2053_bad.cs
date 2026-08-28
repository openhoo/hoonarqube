class Users
{
    void Store(string password)
    {
        var first = HashPassword(password, "pepper");
        var derived = PBKDF2(first, "static-salt", 1000, 32);
    }
}
