public class S4005Bad
{
    public void FetchResource(string uriString) { }
    public void FetchResource(System.Uri uri) { }

    public void Run()
    {
        FetchResource("http://example.com/data");
    }
}
