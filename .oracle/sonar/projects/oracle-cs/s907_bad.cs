class S907Bad
{
    private int Run(bool retry)
    {
        if (retry)
        {
            goto cleanup;
        }

        return 0;

cleanup:
        return 1;
    }
}
