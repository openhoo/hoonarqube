public class Sample
{
    private int total;

    public void Run(int amount)
    {
        total = amount;
        amount += 1;
        System.Console.WriteLine(total + amount);
    }
}
