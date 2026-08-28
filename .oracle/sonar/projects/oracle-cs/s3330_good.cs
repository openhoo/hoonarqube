public class Sample
{
    public void Issue(System.Web.HttpResponse response)
    {
        var ticket = new System.Web.HttpCookie("ticket", "value");
        ticket.Secure = true;
        ticket.HttpOnly = true;
        response.Cookies.Add(ticket);
    }
}
