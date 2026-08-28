class Grader
{
    int Score(int value)
    {
        value = 42;
        return value;
    }

    void Handle()
    {
        try
        {
            System.IO.File.ReadAllText("notes.txt");
        }
        catch (System.IO.IOException error)
        {
            error = null;
        }
    }
}
