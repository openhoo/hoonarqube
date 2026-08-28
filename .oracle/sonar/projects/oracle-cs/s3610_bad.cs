class Checker
{
    void Check(int? value)
    {
        bool equal = value.GetType() == typeof(int?);
        bool different = value.GetType() != typeof(int?);
    }
}
