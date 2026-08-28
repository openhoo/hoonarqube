// S3597 bad: '[OperationContract]' outside any '[ServiceContract]'.
using System.ServiceModel;

namespace Oracle.S3597
{
    internal sealed class OrphanServiceBad
    {
        [OperationContract] // S3597
        public decimal Total() => 42m;

        [OperationContract] // S3597
        public void Audit(string entry)
        {
        }
    }

    [ServiceContract]
    internal sealed class ContractedServiceOkInBadFile
    {
        [OperationContract] // ok: type carries the service contract
        public decimal Total() => 42m;
    }
}
