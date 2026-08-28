public class Sample
{
    public void Issue(System.Web.HttpResponse response)
    {
        var cookie = new System.Web.HttpCookie("session", "value");
        cookie.HttpOnly = true;
        cookie.Secure = true;
        response.Cookies.Add(cookie);
    }
}
