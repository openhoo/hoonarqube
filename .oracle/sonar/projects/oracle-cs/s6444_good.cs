using System;
using System.Text.RegularExpressions;

class S6444Good
{
    bool Check(string input)
    {
        var compiled = new Regex("\\d+", RegexOptions.None, TimeSpan.FromSeconds(5));
        return Regex.IsMatch(input, "\\w+", RegexOptions.None, TimeSpan.FromSeconds(5));
    }
}
