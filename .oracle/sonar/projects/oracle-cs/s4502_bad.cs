// S4502 bad: antiforgery validation switched off.
namespace Oracle.S4502
{
    internal class AntiforgerySettings
    {
        public bool ValidateAntiforgeryToken { get; set; }
        public bool RequireSsl { get; set; }
    }

    internal class AntiforgeryDisabledBad
    {
        private bool antiforgeryEnabled;

        public void Configure(AntiforgerySettings settings)
        {
            settings.ValidateAntiforgeryToken = false; // S4502
            settings.RequireSsl = false; // ok: different switch

            ValidateAntiforgeryToken = false; // S4502
            this.antiforgeryEnabled = false; // S4502

            settings.ValidateAntiforgeryToken = true; // ok: enabled
        }
    }
}
