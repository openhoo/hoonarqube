class S3995Good
{
    public string Load(string path) { return path; }

    public string Load(System.Uri path) { return path.ToString(); }
}
