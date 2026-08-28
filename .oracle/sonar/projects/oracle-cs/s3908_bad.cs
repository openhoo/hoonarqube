public class ChangedEventArgs : EventArgs { }

public delegate void ChangedHandler(object sender, ChangedEventArgs e);

public class Publisher
{
    public event ChangedHandler Changed;
}
