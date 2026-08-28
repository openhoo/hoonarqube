class S3937Good
{
    bool IsSpecial(int code, int other)
    {
        if (code == 1 || code == 3 || code == 5 || code == 7)
        {
            return true;
        }

        if (code == 1 || other == 2 || code == 9)
        {
            return true;
        }

        return false;
    }
}
