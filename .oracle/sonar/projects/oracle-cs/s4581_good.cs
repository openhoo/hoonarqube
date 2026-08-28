// S4581 good: explicit identities instead of all-zero GUIDs.
namespace Oracle.S4581
{
    internal class GuidsGood
    {
        public Guid Fresh() => Guid.NewGuid();

        public Guid ParseKnown()
        {
            return new Guid("b4c3a1d2-0000-0000-0000-000000000000");
        }

        public bool IsDefault(Guid candidate) => candidate == Guid.Empty;
    }
}
