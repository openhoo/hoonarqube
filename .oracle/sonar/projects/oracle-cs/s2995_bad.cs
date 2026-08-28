struct Pair
{
}

class Probes
{
    bool Check(Pair left, Pair right)
    {
        bool structs = ReferenceEquals(left, right);
        bool literals = ReferenceEquals(3, 4);
        bool mixed = ReferenceEquals('x', true);
        return structs || literals || mixed;
    }
}
