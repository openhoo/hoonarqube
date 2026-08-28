// S3928 good: every second-string argument resolves to a real parameter.
using System;

namespace Oracle.S3928
{
    internal class ArgumentNamesGood
    {
        public int Normalize(int count, string label)
        {
            if (count < 0)
            {
                throw new ArgumentOutOfRangeException("count", count, "must be non-negative");
            }

            if (label == null)
            {
                throw new ArgumentNullException("label"); // single-argument form
            }

            if (label.Length == 0)
            {
                throw new ArgumentException("label must not be empty", "count"); // existing parameter
            }

            return count;
        }

        public void Guard(bool ready)
        {
            if (!ready)
            {
                throw new InvalidOperationException("not ready"); // unrelated exception type
            }
        }
    }
}
