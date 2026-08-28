// S4260 bad: '[ConstructorArgument]' names that no constructor accepts.
using System;

namespace Oracle.S4260
{
    internal class WidgetBad
    {
        [ConstructorArgument("scaling")] // S4260: constructor takes 'scale', not 'scaling'
        public int Scale { get; set; }

        [ConstructorArgument("metric")] // S4260: no matching parameter
        private readonly string units = "mm";

        [ConstructorArgument("label")] // ok: matches the constructor below
        public string Label { get; set; }

        public WidgetBad(int scale, string label)
        {
            Scale = scale;
            Label = label;
            units = "cm";
        }
    }
}
