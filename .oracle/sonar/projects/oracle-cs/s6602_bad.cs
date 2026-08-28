using System.Collections.Generic;

class S6602Bad
{
    int FirstPositive(List<int> xs)
    {
        return xs.FirstOrDefault(x => x > 0);
    }
}
