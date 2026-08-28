using System.Collections.Generic;

class S6613Good
{
    int Ends(LinkedList<int> chain)
    {
        chain.AddLast(1);
        return chain.Count;
    }
}
