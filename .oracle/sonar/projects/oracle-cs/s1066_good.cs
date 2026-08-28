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
            else
            {
                Deny();
            }
        }

        if (inner || outer)
        {
            Grant();
        }
        else
        {
            Deny();
        }
    }

    private void Grant()
    {
    }

    private void Deny()
    {
    }
}
