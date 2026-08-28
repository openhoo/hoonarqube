// S4581 bad: parameterless 'new Guid()' yields the all-zero identity.
namespace Oracle.S4581
{
    internal class GuidsBad
    {
        public Guid DefaultId() => new Guid(); // S4581

        public Guid Reset()
        {
            Guid current = new Guid(); // S4581
            return current;
        }
    }
}
