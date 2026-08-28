class Composer
{
    void Build()
    {
        var message = new System.Text.StringBuilder();
        message.Append("hi");
        message.Remove(0, 1);
    }
}
