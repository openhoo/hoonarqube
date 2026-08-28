[Microsoft.AspNetCore.Components.Route("/order/{id:int}/{when:guid}")]
class OrderPage : Microsoft.AspNetCore.Components.ComponentBase
{
    [Microsoft.AspNetCore.Components.Parameter]
    public int Id { get; set; }

    [Microsoft.AspNetCore.Components.Parameter]
    public Guid When { get; set; }
}
