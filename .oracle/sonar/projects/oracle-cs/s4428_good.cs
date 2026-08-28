// S4428 good: creation policy always paired with an export.
using System.ComponentModel.Composition;

namespace Oracle.S4428
{
    [Export(typeof(IWorker))]
    [PartCreationPolicy(CreationPolicy.NonShared)]
    internal sealed class ExportedPolicyGood : IWorker
    {
        public int Work() => 1;
    }

    [Export]
    internal sealed class AlwaysSharedGood
    {
        public int Other() => 2; // default policy without explicit attribute
    }

    internal interface IWorker
    {
        int Work();
    }
}
