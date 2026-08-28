using System.Text.RegularExpressions;

class S6444Bad
{
    bool Check(string input)
    {
        var compiled = new Regex("\\d+");
        return Regex.IsMatch(input, "\\w+");
    }
}
