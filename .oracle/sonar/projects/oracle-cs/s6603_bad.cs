using System.Collections.Generic;
using System.Linq;

class S6603Bad
{
    bool AllNonZero(List<int> xs)
    {
        return xs.All(x => x != 0);
    }
}
