interface ICartEntity
{
    void Load();
}

class CartCaller
{
    void Signal(Microsoft.Azure.WebJobs.Extensions.DurableTask.IDurableEntityClient client)
    {
        client.SignalEntityAsync<ICartEntity>();
    }
}
