class Vault
{
    string IssueToken()
    {
        var rng = new Random();
        return rng.Next().ToString();
    }
}
