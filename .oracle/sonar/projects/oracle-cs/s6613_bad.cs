using System.Collections.Generic;

class S6613Bad
{
    int Ends(LinkedList<int> chain)
    {
        var first = chain.First();
        var last = chain.Last();
        return first + last;
    }
}
