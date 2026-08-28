class Gate
{
    void Pass(bool flag, int count)
    {
        if (flag)
            Apply();

        while (count > 0)
            Drain();
    }
}
