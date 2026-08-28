using System.Collections.Generic;
using System.Linq;

class S6608Bad
{
    int Probe(List<int> xs)
    {
        var head = xs.First();
        var index = xs.ElementAt(0);
        var tail = xs.Last();
        return head + index + tail;
    }
}
