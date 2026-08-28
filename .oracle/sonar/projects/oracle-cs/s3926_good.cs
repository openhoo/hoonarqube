// S3926 good: every optional field is repaired on deserialization.
using System.Runtime.Serialization;

namespace Oracle.S3926
{
    [Serializable]
    internal sealed class VersionedRecordGood
    {
        [OptionalField]
        private int revision;

        [OnDeserializing]
        private void Initialize(StreamingContext context)
        {
            revision = 1;
        }

        [OnDeserialized]
        private void Repair(StreamingContext context)
        {
            if (revision == 0)
            {
                revision = 1;
            }
        }
    }

    [Serializable]
    internal sealed class PlainRecordGood
    {
        private int revision; // no optional field, no hook needed
    }
}
