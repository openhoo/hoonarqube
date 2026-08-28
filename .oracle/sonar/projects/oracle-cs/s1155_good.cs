using System.Collections.Generic;
using System.Linq;

class S1155Good
{
    int Check(List<int> items)
    {
        if (items.Count == 1)
        {
            return 1;
        }

        if (items.Count > 0)
        {
            return 2;
        }

        if (items.Any())
        {
            return 3;
        }

        return items.Count != 0 ? 4 : 5;
    }
}
