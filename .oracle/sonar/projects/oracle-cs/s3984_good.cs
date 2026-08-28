public class Sample
{
    public bool Guard(object value)
    {
        if (value == null)
        {
            throw new System.ArgumentNullException(nameof(value));
        }

        return true;
    }
}
