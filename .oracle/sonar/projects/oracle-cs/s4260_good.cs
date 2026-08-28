// S4260 good: every '[ConstructorArgument]' names a real constructor parameter.
using System.ComponentModel;

namespace Oracle.S4260
{
    internal class WidgetGood
    {
        [ConstructorArgument("scale")]
        public int Scale { get; set; }

        [ConstructorArgument("tag")]
        private readonly string tag = "w";

        [Description("unrelated attribute, no constructor argument")]
        public string Note { get; set; }

        public WidgetGood(int scale, string tag)
        {
            Scale = scale;
            this.tag = tag;
            Note = "";
        }
    }
}
