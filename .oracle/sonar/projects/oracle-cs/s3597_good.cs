// S3597 good: operations live under service contracts.
using System.ServiceModel;

namespace Oracle.S3597
{
    [ServiceContract]
    internal sealed class ContractedServiceGood
    {
        [OperationContract]
        public decimal Total() => 42m;

        [OperationContract(IsOneWay = true)]
        public void Ping()
        {
        }
    }

    internal sealed class HelperGood
    {
        public void InternalOnly()
        {
        } // no operation contract at all
    }
}
