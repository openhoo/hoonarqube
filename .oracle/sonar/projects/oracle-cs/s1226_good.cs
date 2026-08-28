class Grader
{
    int Score(int value)
    {
        return value * 2;
    }

    void Handle()
    {
        try
        {
            System.IO.File.ReadAllText("notes.txt");
        }
        catch (System.IO.IOException error)
        {
            Log(error.Message);
        }
    }
}
