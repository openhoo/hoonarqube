public class Sample
{
    public virtual int VirtualAnswer()
    {
        return 42;
    }

    public static void Main(string[] args)
    {
        System.Console.WriteLine("entry");
    }

    public int Computed()
    {
        const int answer = 42;
        return answer;
    }
}
