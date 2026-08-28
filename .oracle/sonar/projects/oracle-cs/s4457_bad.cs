public class Sample
{
    public static async System.Threading.Tasks.Task SaveAsync(string name, int count)
    {
        if (name == null)
        {
            throw new System.ArgumentNullException(nameof(name));
        }
        if (count < 0)
        {
            throw new System.ArgumentOutOfRangeException(nameof(count));
        }
        await System.Threading.Tasks.Task.Delay(1).ConfigureAwait(false);
    }
}
