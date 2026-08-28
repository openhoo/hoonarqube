public class Cursor
{
    public int Read(byte[] buffer, int offset)
    {
        return buffer.Length + offset;
    }

    internal unsafe void Write(byte* target, int length)
    {
    }

    internal unsafe delegate int Scan(char* start);
}
