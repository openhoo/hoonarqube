public class SectionWeight
{
    public int Heft(int option)
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
                option += 10;
                option += 11;
                option += 12;
                option += 13;
                option += 14;
                option += 15;
                option += 16;
                option += 17;
                option += 18;
                option += 19;
                option += 20;
                option += 21;
                option += 22;
                option += 23;
                option += 24;
                option += 25;
                break;
            case 1:
                option += 200;
                break;
            default:
                break;
        }

        return option;
    }
}
