public class Sample
{
    public void Step(int seed)
    {
        seed++;
        for (var i = 0; i < 10; i++)
        {
            seed += i;
        }
        seed--;
    }
}
