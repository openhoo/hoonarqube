using System.Text.RegularExpressions;

class S5856Good
{
    bool Digits(string input)
    {
        return Regex.IsMatch(input, "^\\d{4}$");
    }

    System.Text.RegularExpressions.Regex Words()
    {
        return new Regex("[a-z]+");
    }
}
