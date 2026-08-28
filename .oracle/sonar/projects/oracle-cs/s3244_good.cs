class S3244Good
{
    private System.EventHandler stored;

    void Wire()
    {
        Handler += (sender, args) => { };
        Handler -= stored;
    }

    event System.EventHandler Handler;
}
