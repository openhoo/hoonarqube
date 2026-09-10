#line 1 "LoopComponent.razor"
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Rendering;

namespace Roadmap.Blazor;

public sealed class GeneratedLoop : ComponentBase
{
    protected override void BuildRenderTree(RenderTreeBuilder builder)
    {
        for (var index = 0; index < 3; index++)
        {
            builder.AddAttribute(0, "onclick", EventCallback.Factory.Create(this, () => Handle(index)));
        }
    }

    private void Handle(int value) => _ = value;
}
#line default
