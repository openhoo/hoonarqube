using System.Collections.Generic;

class S6605Bad
{
    bool HasNegative(List<int> xs)
    {
        return xs.Any(x => x < 0);
    }
}
