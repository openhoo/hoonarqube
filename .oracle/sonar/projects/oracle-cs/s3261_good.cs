namespace Populated.Region
{
    public class Worker
    {
        public void Run()
        {
            Ticks++;
        }

        public int Ticks { get; set; }
    }
}
