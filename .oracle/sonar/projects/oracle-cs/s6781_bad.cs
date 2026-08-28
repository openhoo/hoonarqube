public class Sample
{
    public Microsoft.IdentityModel.Tokens.SymmetricSecurityKey Key()
    {
        return new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
            System.Text.Encoding.UTF8.GetBytes("aa55aa55bb66bb77cc88cc88dd99dd99"));
    }
}
