public class S2757Bad
{
    public void Work(int amount, int step)
    {
        int total = 0;
        total =+ amount;
        int count = 0;
        count =+ step;
        System.Console.WriteLine(total + count);
    }
}
