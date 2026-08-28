class Shifter
{
    int Shift(int page, int mask)
    {
        dynamic dynamicPage = page;
        dynamic dynamicMask = mask;
        var a = dynamicPage << "index";
        var b = dynamicMask >> false;
        var c = dynamicPage << true;
        var d = dynamicMask >> null;
        return (int)(a + b + c + d);
    }
}
