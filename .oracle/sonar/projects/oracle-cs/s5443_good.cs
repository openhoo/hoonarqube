public class Sample
{
    public void WritePrivate()
    {
        var userDir = System.Environment.GetFolderPath(System.Environment.SpecialFolder.ApplicationData);
        var privateSpool = @"C:\ProgramData\MyApp\Spool\out.dat";
        var homePath = "/home/svc-app/spool/report.csv";
        var appData = "%APPDATA%\\cache.bin";
        var tmpPrefix = "/temporary/scratch/x.dat";
        var systemDir = @"C:\Windows\System32\spool";
        System.IO.File.WriteAllText(userDir + privateSpool + homePath + appData + tmpPrefix + systemDir, "payload");
    }
}
