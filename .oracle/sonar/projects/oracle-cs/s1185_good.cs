class S1185GoodBase
{
    public virtual string Name() { return "value"; }

    public virtual string Other() { return "other"; }
}

class S1185Good : S1185GoodBase
{
    public override string Name() { return base.Other(); }

    public void Run() { }

    public override string ToString()
    {
        var text = base.ToString();
        return text == null ? "" : text.Trim();
    }
}
