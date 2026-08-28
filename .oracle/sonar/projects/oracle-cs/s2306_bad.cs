class S2306Bad
{
    private int async;

    private int Get()
    {
        int await = async;

        return await;
    }
}
