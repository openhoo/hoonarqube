class Bus
{
    delegate void Handler();

    void Route()
    {
        Handler first = First;
        Handler second = Second;
        Handler pipeline = first + second;
        var trimmed = pipeline - (first + second);
    }

    static void First() { }
    static void Second() { }
}
