using System.Collections.Generic;
using System.Linq;

class S6609Bad
{
    int Low(HashSet<int> set)
    {
        return set.Min();
    }

    int High(SortedSet<int> sorted)
    {
        return sorted.Max();
    }
}
