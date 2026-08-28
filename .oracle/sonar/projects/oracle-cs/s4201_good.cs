public class TypeCheck
{
    public bool IsText(object value)
    {
        return value is string;
    }
}
