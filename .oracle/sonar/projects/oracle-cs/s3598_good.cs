// S3598 good: one-way operations return void.
using System.ServiceModel;

namespace Oracle.S3598
{
    [ServiceContract]
    internal sealed class LedgerServiceGood
    {
        [OperationContract(IsOneWay = true)]
        public void Notify(string entry)
        {
        }

        [OperationContract]
        public decimal Total() => 42m;

        [OperationContract(IsTerminating = true)]
        public void Close()
        {
        }
    }
}
