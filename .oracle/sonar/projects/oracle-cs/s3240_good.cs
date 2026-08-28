public class Sample
{
    public bool Check(bool flag, bool gate)
    {
        bool plain = !flag;
        bool conjunct = flag && gate;
        bool chosen = flag ? gate : !gate;
        return plain || conjunct || chosen;
    }
}
