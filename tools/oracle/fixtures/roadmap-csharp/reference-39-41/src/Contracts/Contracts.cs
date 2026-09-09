namespace Roadmap.Contracts;

public class Depth0 { }
public class Depth1 : Depth0 { }
public class Depth2 : Depth1 { }
public class Depth3 : Depth2 { }
public class Depth4 : Depth3 { }
public class Depth5 : Depth4 { }
public class Depth6 : Depth5 { }

public interface IKnown { }
public interface IOther { }
public sealed class SealedKnown : IKnown { }
public sealed class SealedUnrelated { }
public class OpenKnown : IKnown { }
public class OpenUnrelated { }

public sealed class Dependency01 { }
public sealed class Dependency02 { }
public sealed class Dependency03 { }
public sealed class Dependency04 { }
public sealed class Dependency05 { }
public sealed class Dependency06 { }
public sealed class Dependency07 { }
public sealed class Dependency08 { }
public sealed class Dependency09 { }
public sealed class Dependency10 { }
public sealed class Dependency11 { }
public sealed class Dependency12 { }
public sealed class Dependency13 { }
public sealed class Dependency14 { }
public sealed class Dependency15 { }
public sealed class Dependency16 { }
public sealed class Dependency17 { }
public sealed class Dependency18 { }
public sealed class Dependency19 { }
public sealed class Dependency20 { }
public sealed class Dependency21 { }
public sealed class Dependency22 { }
public sealed class Dependency23 { }
public sealed class Dependency24 { }
public sealed class Dependency25 { }
public sealed class Dependency26 { }
public sealed class Dependency27 { }
public sealed class Dependency28 { }
public sealed class Dependency29 { }
public sealed class Dependency30 { }
public sealed class Dependency31 { }
public sealed class Dependency32 { }

public class BaseRecord
{
    public int Id { get; set; }
}

public class DerivedRecord : BaseRecord
{
    public string Label { get; set; } = string.Empty;
}

public interface IProducer<T>
{
    T Produce();
}

public interface IConsumer<T>
{
    void Consume(T value);
}

public interface IInvariant<T>
{
    T Transform(T value);
}

public interface IContainer<T>
{
    IReadOnlyList<T> Items { get; }
}

public interface IContravariant<T>
{
    void Accept(IReadOnlyList<T> value);
}

public readonly struct RefValue
{
    public int Value { get; init; }
}

public static class GenericApi
{
    public static void RefMethod<T>(ref T value) { }
    public static void OutMethod<T>(out T value) { value = default!; }
    public static void InMethod<T>(in T value) { _ = value; }
}
