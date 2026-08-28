public class SectionSpan
{
    public int Stretch(int option)
    {
        switch (option)
        {
            case 0:
                option += 1;
                option += 2;
                option += 3;
                option += 4;
                option += 5;
                option += 6;
                break;
            case 1:
                option += 10;
                break;
            default:
                break;
        }

        return option;
    }
}
