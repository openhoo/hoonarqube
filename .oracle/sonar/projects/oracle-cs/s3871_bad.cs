internal class FaultDetail : Exception
{
}

class MissingConfigException : System.ArgumentException
{
}

public class JobRunner
{
    private sealed class LoadException : System.InvalidOperationException
    {
    }
}
