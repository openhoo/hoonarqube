public class Sample
{
    public void Hijackable()
    {
        var first = System.IO.Path.GetTempFileName();
        var second = System.IO.Path.GetTempFileName();
        System.IO.File.WriteAllText(first + second, "payload");
    }
}
