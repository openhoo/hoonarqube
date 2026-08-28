public class S2302Bad
{
    public void Save(string userId)
    {
        throw new System.ArgumentException("userId");
    }
}
