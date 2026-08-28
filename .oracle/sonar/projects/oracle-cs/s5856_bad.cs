using System.Text.RegularExpressions;

class S5856Bad
{
    bool Check(string input)
    {
        var broken = new Regex("([a-z");
        return Regex.IsMatch(input, "[z-a]");
    }
}
