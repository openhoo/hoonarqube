class S3244Bad
{
    event System.EventHandler Handler;

    void Wire()
    {
        Handler += (sender, args) => { };
        Handler -= delegate { };
        Handler -= (sender, args) => { };
    }
}
