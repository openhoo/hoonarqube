public class FilterPanel : Microsoft.AspNetCore.Components.ComponentBase
{
    [Microsoft.AspNetCore.Components.Parameter]
    [Microsoft.AspNetCore.Components.SupplyParameterFromQuery]
    public string Term { get; set; }

    [Microsoft.AspNetCore.Components.Parameter]
    [Microsoft.AspNetCore.Components.SupplyParameterFromQuery]
    public int Page { get; set; }
}
