class S1155Bad
{
    int Check(System.Collections.Generic.IEnumerable<int> items)
    {
        if (items.Count() <= 0)
        {
            return 1;
        }

        if (0 == items.Count())
        {
            return 2;
        }

        return 0;
    }
}
