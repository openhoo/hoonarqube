class S3247Bad
{
    int Convert(object item)
    {
        if (item is string)
        {
            var text = (string)item;
            return text.Length;
        }
        return 0;
    }
}
