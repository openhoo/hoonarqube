public class S2970Bad
{
    public void Work(bool flag, bool state, bool ready)
    {
        NFluent.Check.That(flag);
        if (ready)
        {
            NFluent.Check.That(state);
        }
    }
}
