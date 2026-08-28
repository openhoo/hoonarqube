public class Shutdown
{
    public void Bail()
    {
        System.Environment.Exit(-1);
        Environment.FailFast("fatal");
        System.Windows.Forms.Application.Exit();
    }
}
