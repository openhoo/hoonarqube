public class Sample
{
    public string Describe(int value)
    {
        switch (value)
        {
            case 1:
                return "one";
            default:
                break;
        }

        for (int i = 0; i < 3; i++)
        {
            System.Console.WriteLine(i);
        }

        return "done";
    }
}
