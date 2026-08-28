using System.Collections.Generic;
using System.Linq;

class S6609Good
{
    int Low(HashSet<int> set, List<int> values)
    {
        var smallest = set.Min(x => x * 2);
        return smallest + values.Min();
    }
}
