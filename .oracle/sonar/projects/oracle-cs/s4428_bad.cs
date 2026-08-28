// S4428 bad: creation policy without an export.
using System.ComponentModel.Composition;

namespace Oracle.S4428
{
    [PartCreationPolicy(CreationPolicy.NonShared)] // S4428
    internal sealed class PolicyWithoutExportBad
    {
        public int Work() => 1;
    }

    [PartCreationPolicy(CreationPolicy.Shared)] // S4428
    internal sealed class SharedWithoutExportBad
    {
        public int Other() => 2;
    }

    [Export(typeof(IWorker))]
    [PartCreationPolicy(CreationPolicy.Any)] // ok: paired with an export
    internal sealed class ExportedOkInBadFile : IWorker
    {
        public int Work() => 3;
    }

    internal interface IWorker
    {
        int Work();
    }
}
