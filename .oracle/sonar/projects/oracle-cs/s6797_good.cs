[Microsoft.AspNetCore.Components.Route("/filters")]
class Filters : Microsoft.AspNetCore.Components.ComponentBase
{
    [Microsoft.AspNetCore.Components.Parameter]
    [Microsoft.AspNetCore.Components.SupplyParameterFromQuery]
    public int Count { get; set; }

    [Microsoft.AspNetCore.Components.Parameter]
    [Microsoft.AspNetCore.Components.SupplyParameterFromQuery]
    public Guid? Row { get; set; }

    [Microsoft.AspNetCore.Components.Parameter]
    [Microsoft.AspNetCore.Components.SupplyParameterFromQuery]
    public decimal[] Amounts { get; set; }
}
