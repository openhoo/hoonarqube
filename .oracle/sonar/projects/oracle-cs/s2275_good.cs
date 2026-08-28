class S2275Good
{
    string Render(object one)
    {
        var slotted = string.Format("{0}", one);
        var escaped = string.Format("{{0}} literal", one);
        return slotted + escaped;
    }
}
