class S4005Good
{
    string Fetch(System.Net.WebClient client, string address)
    {
        return client.DownloadString(new System.Uri(address));
    }
}
