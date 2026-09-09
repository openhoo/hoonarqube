using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Rendering;

namespace Roadmap.Semantic;

public sealed class BlazorInvocationCases : ComponentBase
{
    protected override void BuildRenderTree(RenderTreeBuilder builder)
    {
        for (var index = 0; index < 3; index++)
        {
            builder.AddAttribute(0, "onclick", EventCallback.Factory.Create(this, () => Handle(index)));
        }
    }

    private void Handle(int value) => _ = value;

    public static void NonBlazorLikeLoop()
    {
        for (var index = 0; index < 3; index++)
        {
            Action callback = () => Console.WriteLine(index);
            callback();
        }
    }

    public static void UserNamedBuilderLoop()
    {
        var builder = new UserNamedBuilder();
        for (var index = 0; index < 3; index++)
        {
            builder.AddAttribute("onclick", () => Console.WriteLine(index));
        }
    }

    private sealed class UserNamedBuilder
    {
        public void AddAttribute(string name, Action callback)
        {
            _ = name;
            callback();
        }
    }
}
