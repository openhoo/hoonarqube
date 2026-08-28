public class Sample
{
    ~Sample()
    {
        Ready = false;
    }

    private bool Ready { get; set; }
}
