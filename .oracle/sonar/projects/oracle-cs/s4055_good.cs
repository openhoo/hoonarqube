public class GreetingWindow : Window
{
    public void Render(string title)
    {
        this.Title = title;
        this.Header = BuildCaption();
        Width = 320;
    }
}
