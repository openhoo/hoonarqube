public class GradeRouter
{
    public string Describe(int grade)
    {
        switch (grade)
        {
            case 0:
                return "zero";
            default:
                return "many";
        }
    }
}
