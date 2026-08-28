using System;

public sealed class NativeOracle
{
    public void Empty()
    {
    }

    public void LongLine() => Console.WriteLine("This deliberately long C sharp source line exceeds the default SonarQube line length threshold by including enough stable fixture text for an exact native scanner smoke test.");
}
