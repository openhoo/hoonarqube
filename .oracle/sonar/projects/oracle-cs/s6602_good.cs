using System.Collections.Generic;

class S6602Good
{
    int First(List<int> xs)
    {
        return xs.FirstOrDefault();
    }

    int Unknown(System.Collections.Generic.IEnumerable<int> seq)
    {
        return seq.FirstOrDefault(x => x > 0);
    }
}
