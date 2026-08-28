public class DepthWalk
{
    public void Traverse(int[] items, bool running)
    {
        for (int i = 0; i < items.Length; i++)
        {
            foreach (int item in items)
            {
                while (running)
                {
                    if (item >= 0)
                    {
                        do
                        {
                            running = false;
                        }
                        while (running);
                    }
                }
            }
        }
    }
}
