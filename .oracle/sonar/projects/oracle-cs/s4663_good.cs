using System;

/// <summary>Annotates processed records.</summary>
class Annotator
{
    // Records are annotated after validation completes.
    /* The annotation pass always runs last. */
    void Mark()
    {
        Console.WriteLine("marked");
    }
}
