// S3926 bad: optional fields without a deserialization hook.
using System.Runtime.Serialization;

namespace Oracle.S3926
{
    [Serializable]
    internal sealed class VersionedRecordBad
    {
        [OptionalField] // S3926
        private int revision;

        [OptionalField] // S3926
        private string migratedBy;
    }

    [Serializable]
    internal sealed class HookedRecordOkInBadFile
    {
        [OptionalField] // ok: hook below repairs it
        private string note;

        [OnDeserialized]
        private void OnDeserialized(StreamingContext context)
        {
            note ??= string.Empty;
        }
    }
}
