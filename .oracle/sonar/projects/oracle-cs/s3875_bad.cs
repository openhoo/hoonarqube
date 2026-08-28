public class Wrapper
{
    public static bool operator ==(Wrapper left, Wrapper right)
    {
        return true;
    }

    public static bool operator !=(Wrapper left, Wrapper right)
    {
        return false;
    }
}

public class Holder
{
    public class Nested
    {
        public static bool operator ==(Nested a, Nested b)
        {
            return false;
        }

        public static bool operator !=(Nested a, Nested b)
        {
            return !a.Equals(b);
        }
    }
}
