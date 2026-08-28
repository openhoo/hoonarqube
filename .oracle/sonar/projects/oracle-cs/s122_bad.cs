class Pipeline
{
    void Run()
    {
        Load();
        Save(); Archive();
        Purge();
    }
}
