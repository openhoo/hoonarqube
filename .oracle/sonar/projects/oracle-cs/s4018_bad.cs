public class Repository
{
    public TEntity GetDefault<TEntity>()
    {
        return default(TEntity);
    }

    public void Fill<TEntity>(int count)
    {
    }
}
