// S3598 bad: one-way operations returning values.
using System.ServiceModel;

namespace Oracle.S3598
{
    [ServiceContract]
    internal sealed class LedgerServiceBad
    {
        [OperationContract(IsOneWay = true)] // S3598: returns decimal
        public decimal Total() => 42m;

        [OperationContract(IsOneWay = true)] // S3598: returns string
        public string Name() => "ledger";

        [OperationContract] // ok: default two-way
        public void Audit(string entry)
        {
        }

        [OperationContract(IsOneWay = true)] // ok: legal void one-way
        public void FireAndForget(string entry)
        {
        }
    }
}
