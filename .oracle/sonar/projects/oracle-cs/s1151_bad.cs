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
                option += 7;
                option += 8;
                option += 9;
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
