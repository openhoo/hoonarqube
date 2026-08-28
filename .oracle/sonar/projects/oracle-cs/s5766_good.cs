[Serializable]
class ImportSession
{
    [OnDeserializing]
    private void Before(StreamingContext context)
    {
    }
}
