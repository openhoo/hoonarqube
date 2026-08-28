class S3247Good
{
    int Convert(object item)
    {
        var text = (string)item;
        var length = text.Length;
        return length + 1;
    }
}
