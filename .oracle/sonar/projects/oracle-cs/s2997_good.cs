class Factory
{
    System.IO.StreamWriter Create()
    {
        using (var writer = new System.IO.StreamWriter("app.log"))
        {
            writer.AutoFlush = true;
        }
        return writer;
    }
}
