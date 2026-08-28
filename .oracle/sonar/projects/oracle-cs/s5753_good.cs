public class Sample
{
    public void HardenedPage()
    {
        var directive = "<%@ Page ValidateRequest=\"true\" %>";
        var setting = "ValidateInput=true";
        var other = "<compilation debug=\"false\" />";
        System.Console.WriteLine(directive + setting + other);
        ValidateInput(true);
        this.ValidateInput(false);
    }

    private void ValidateInput(bool enable)
    {
    }
}
