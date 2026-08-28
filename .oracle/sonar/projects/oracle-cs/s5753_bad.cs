public class Sample
{
    public void DisabledPage()
    {
        var directive = "<%@ Page ValidateRequest=\"false\" %>";
        var setting = "pageConfiguration.ValidateRequest=false";
        System.Console.WriteLine(directive + setting);
        ValidateInput(false);
    }

    private void ValidateInput(bool enable)
    {
    }
}
