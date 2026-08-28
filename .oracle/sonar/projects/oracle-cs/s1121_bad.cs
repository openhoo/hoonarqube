public class Sample
{
    public void Run()
    {
        int first;
        int second;
        int total;
        total = (first = 1) + (second = 2);
        if ((second = 3) > 0)
        {
            System.Console.WriteLine(total + second);
        }
    }
}
