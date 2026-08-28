using System;
using System.IO;

class OrderProcessor
{
    void Process(bool ready)
    {
        if (ready)
        {
            Dispatch();
        }
        else
        {
            Hold();
        }

        try
        {
            Open();
        }
        catch (IOException error)
        {
            Log(error);
        }
        finally
        {
            Close();
        }
    }
}
