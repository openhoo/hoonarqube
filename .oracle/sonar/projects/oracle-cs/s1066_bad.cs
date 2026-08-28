public class Gatekeeper
{
    public void Check(bool outer, bool inner)
    {
        if (outer)
        {
            if (inner)
            {
                Grant();
            }
        }

        if (inner)
            if (outer)
                Grant();
    }

    private void Grant()
    {
    }
}
