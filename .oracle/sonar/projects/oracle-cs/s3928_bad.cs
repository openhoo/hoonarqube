// S3928 bad: 'paramName' arguments name nothing on the throwing method.
using System;

namespace Oracle.S3928
{
    internal class ArgumentNamesBad
    {
        public void Store(string payload, string checksum)
        {
            if (payload == null)
            {
                throw new ArgumentNullException("payload", "data"); // S3928: 'data' is not a parameter
            }

            if (checksum == null)
            {
                throw new ArgumentOutOfRangeException("checksum", "hash"); // S3928
            }
        }

        public void Validate(int quantity, string tag)
        {
            if (quantity < 0)
            {
                throw new ArgumentException("must be non-negative", "amount"); // S3928
            }

            if (tag != null && tag.Length == 0)
            {
                throw new ArgumentException("must not be empty", "tag"); // ok: names 'tag'
            }
        }
    }
}
