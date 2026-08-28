[Microsoft.AspNetCore.Components.Route("/filters")]
class Filters : Microsoft.AspNetCore.Components.ComponentBase
{
    [Microsoft.AspNetCore.Components.Parameter]
    [Microsoft.AspNetCore.Components.SupplyParameterFromQuery]
    public List<int> Pages { get; set; }

    [Microsoft.AspNetCore.Components.Parameter]
    [Microsoft.AspNetCore.Components.SupplyParameterFromQuery]
    public Dictionary<string, int> Map { get; set; }
}
