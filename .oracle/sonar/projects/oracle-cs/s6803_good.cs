[Microsoft.AspNetCore.Components.Route("/filter")]
public class FilterPanel : Microsoft.AspNetCore.Components.ComponentBase
{
    [Microsoft.AspNetCore.Components.Parameter]
    [Microsoft.AspNetCore.Components.SupplyParameterFromQuery]
    public string Term { get; set; }
}

public class Plain
{
    public string Term { get; set; }
}
