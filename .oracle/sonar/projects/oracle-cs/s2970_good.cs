public class S2970Good
{
    public void Work(bool flag, string name)
    {
        NFluent.Check.That(flag).IsEqualTo(true);
        NFluent.Check.That(name).IsEqualTo("oracle");
    }
}
