// S4502 good: antiforgery stays enabled; unrelated switches untouched.
namespace Oracle.S4502
{
    internal class AntiforgerySettings
    {
        public bool ValidateAntiforgeryToken { get; set; }
        public bool RequireSsl { get; set; }
    }

    internal class AntiforgeryGood
    {
        private bool antiforgeryEnabled;

        public void Configure(AntiforgerySettings settings)
        {
            settings.ValidateAntiforgeryToken = true; // enabled
            settings.RequireSsl = false; // unrelated setting may be off
            this.antiforgeryEnabled = true;
            antiforgeryEnabled = !antiforgeryEnabled; // compound toggle, not plain '='
        }
    }
}
