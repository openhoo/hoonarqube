public delegate void ResultHandler(string result);

public class Publisher
{
    public event ResultHandler Completed;
}
