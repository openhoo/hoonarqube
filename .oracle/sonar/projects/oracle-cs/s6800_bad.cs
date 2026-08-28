[Microsoft.AspNetCore.Components.Route("/order/{id:int}/{when:guid}")]
class OrderPage : Microsoft.AspNetCore.Components.ComponentBase
{
    [Microsoft.AspNetCore.Components.Parameter]
    public long Id { get; set; }

    [Microsoft.AspNetCore.Components.Parameter]
    public DateTime When { get; set; }
}
