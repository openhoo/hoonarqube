public class Sample
{
    private bool _released;

    ~Sample()
    {
        _released = true;
    }
}
