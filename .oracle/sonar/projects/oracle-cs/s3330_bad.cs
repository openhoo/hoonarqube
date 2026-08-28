public class Sample
{
    public void Issue(System.Web.HttpResponse response)
    {
        var ticket = new System.Web.HttpCookie("ticket", "value");
        ticket.Secure = true;
        response.Cookies.Add(ticket);
    }
}
