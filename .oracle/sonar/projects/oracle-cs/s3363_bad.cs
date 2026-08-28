using System;
using System.ComponentModel.DataAnnotations;

public class S3363Bad
{
    public DateTime Id { get; set; } // S3363

    [Key]
    public DateTime PersonIdentifier { get; set; } // S3363
}
