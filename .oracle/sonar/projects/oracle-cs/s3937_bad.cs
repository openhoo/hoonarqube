class S3937Bad
{
    bool IsSpecial(int code)
    {
        int thousand = 100_0;
        int tenThousand = 100_00;
        return code == thousand || code == tenThousand;
    }
}
