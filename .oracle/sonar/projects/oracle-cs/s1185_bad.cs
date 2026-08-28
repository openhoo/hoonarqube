class S1185GoodBase
{
    public virtual string Name() { return "value"; }
}

class S1185Bad : S1185GoodBase
{
    public override string Name() { return base.Name(); }
}
