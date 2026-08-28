public class Sample
{
    ~Sample()
    {
        throw new System.InvalidOperationException("finalizer cannot throw");
    }
}
