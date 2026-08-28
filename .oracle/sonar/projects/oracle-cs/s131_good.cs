public class ModeSwitch
{
    public int Select(int mode)
    {
        switch (mode)
        {
            case 1:
                return 10;
            case 2:
                return 20;
            case 3:
                return 30;
            default:
                return 0;
        }
    }
}
