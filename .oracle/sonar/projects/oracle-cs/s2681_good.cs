public class BracedBodies
{
    public void Run(bool flag)
    {
        if (flag)
        {
            Report("first");
        }

        while (flag)
        {
            Step(2);
        }

        if (flag)
            Report("single-line");
    }

    private void Report(string message)
    {
    }

    private void Step(int count)
    {
    }
}
