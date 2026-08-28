public class GradeRouter
{
    public string Describe(int grade)
    {
        switch (grade)
        {
            case 0:
                return "zero";
            case 1:
                return "one";
            case 2:
                return "two";
            default:
                return "many";
        }
    }
}
