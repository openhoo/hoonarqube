public class Sample
{
    public void WritePublic()
    {
        var log = "/tmp/app-crash.log";
        var spool = "/var/tmp/print-spool.dat";
        var cache = @"C:\Windows\Temp\cache.bin";
        var export = "%TEMP%\\report.csv";
        System.IO.File.WriteAllText(log + spool + cache + export, "payload");
    }
}
