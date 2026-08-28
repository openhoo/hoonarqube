public class ImportException : System.Exception
{
    public ImportException()
    {
    }

    public ImportException(string message)
        : base(message)
    {
    }
}

public class ExportError : System.Exception
{
}
