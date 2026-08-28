using System.Collections.Generic;
using System.Linq;

class S6608Good
{
    int Head(List<int> xs)
    {
        if (xs.Count == 0)
        {
            return -1;
        }

        return xs[0];
    }

    int WithPredicate(List<int> xs)
    {
        return xs.First(x => x > 0);
    }
}
