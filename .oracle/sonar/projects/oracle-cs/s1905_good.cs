class Conversions
{
    void Kept()
    {
        int? maybe = (int?)7;
        double? ratio = (double?)1.5;
        object boxed = 3;
        var unboxed = (int)boxed;
        var parsed = (CustomId)42;
    }
}
