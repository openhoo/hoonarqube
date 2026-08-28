using System.Collections.Generic;
using System.Linq;

class S6605Good
{
    bool HasNegative(List<int> xs, System.Collections.Generic.IEnumerable<int> seq)
    {
        if (xs.Any())
        {
            return true;
        }

        return seq.Any(x => x < 0);
    }
}
