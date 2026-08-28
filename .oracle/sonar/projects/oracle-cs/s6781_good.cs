public class Sample
{
    public Microsoft.IdentityModel.Tokens.SymmetricSecurityKey Key(byte[] configSecret)
    {
        return new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(configSecret);
    }

    public Microsoft.IdentityModel.Tokens.SymmetricSecurityKey KeyFromString(string configKey)
    {
        return new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
            System.Text.Encoding.UTF8.GetBytes(configKey));
    }
}
