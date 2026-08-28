enum Style
{
    Bold,
    Italic
}

class Painter
{
    int Mix(Style style)
    {
        return (int)(style & Style.Bold);
    }
}
