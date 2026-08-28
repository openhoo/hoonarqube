using System.Collections.Generic;
using System.Linq;

class S6603Good
{
    bool AllPositive(List<int> xs, int[] values)
    {
        if (xs.TrueForAll(x => x > 0))
        {
            return true;
        }

        return System.Array.TrueForAll(values, x => x != 0);
    }
}
