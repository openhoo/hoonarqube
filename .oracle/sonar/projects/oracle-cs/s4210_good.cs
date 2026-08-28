using System;
using System.Windows.Forms;

public class Program
{
    [STAThread]
    public static void Main()
    {
        Application.Run(new AppForm());
    }

    private static void Bootstrap()
    {
        Console.WriteLine("boot");
    }
}

public class AppForm : Form
{
}
