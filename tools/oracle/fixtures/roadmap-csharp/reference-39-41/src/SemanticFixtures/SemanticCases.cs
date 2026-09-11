using D01 = Roadmap.Contracts.Dependency01;
using D02 = Roadmap.Contracts.Dependency02;
using ObjectAlias = System.Object;
using Roadmap.Contracts;

namespace Roadmap.Semantic;

public class LocalDepth0 { }
public class LocalDepth1 : LocalDepth0 { }
public class LocalDepth2 : LocalDepth1 { }
public class LocalDepth3 : LocalDepth2 { }
public class LocalDepth4 : LocalDepth3 { }
public class LocalDepth5 : LocalDepth4 { }
public class LocalDepth6 : LocalDepth5 { }

public class DeepAbove : LocalDepth6 { }
public class DeepAt : LocalDepth5 { }
public class FilteredExternalDepth : Depth6 { }

public sealed class CoupledAbove
{
    public D01 One { get; } = new();
    public D02 Two { get; } = new();
    public Dependency03 Three { get; } = new();
    public Dependency04 Four { get; } = new();
    public Dependency05 Five { get; } = new();

    public int Repeat(D01 first, D01 second)
    {
        return One.GetHashCode() + first.GetHashCode() + second.GetHashCode();
    }
}

public sealed class CoupledAt
{
    public Dependency01 One { get; } = new();
    public Dependency02 Two { get; } = new();
    public Dependency03 Three { get; } = new();
}

public sealed class CoupledRepeated
{
    public Dependency01 One { get; } = new();
    public Dependency01 Two { get; } = new();
    public Dependency02 Three { get; } = new();
}
public class ExternalOther : IOther { }

public class OpenPossibleBase { }

public class OpenOther : OpenPossibleBase, IOther { }

public static class ImpossibleCastCases
{
    public static IOther Bad(OpenUnrelated value) => (IOther)value;

    public static IOther Possible(OpenPossibleBase value) => (IOther)value;

    public static IKnown Known(OpenKnown value) => (IKnown)value;

    public static IOther SealedControl() => (IOther)(object)new SealedUnrelated();
}

public static class BaseParameterCases
{
    public static int Bad(DerivedRecord value) => value.Id;

    public static int Good(BaseRecord value) => value.Id;

    public static string NeedsDerived(DerivedRecord value) => value.Label;

    public static int BadLocal(DerivedParameter value) => value.Id;

    public static int GoodLocal(BaseParameter value) => value.Id;
}

public class BaseParameter
{
    public int Id { get; set; }
}

public class DerivedParameter : BaseParameter
{
    public string Extra { get; set; } = string.Empty;
}

public interface OutputNeedsOut<T>
{
    T Get();
}

public interface InputNeedsIn<T>
{
    void Put(T value);
}

public interface NestedOutputNeedsOut<T>
{
    IReadOnlyList<T> GetAll();
}

public interface NestedInputInvariant<T>
{
    void Put(IReadOnlyList<T> values);
}

public interface InvariantControl<T>
{
    T Transform(T value);
}

public interface ConstrainedOutput<T> where T : BaseRecord
{
    T GetConstrained();
}

public delegate T OutputDelegate<T>();
public delegate void InputDelegate<T>(T value);

public static class RefParameterCases
{
    public static void RefObject(ref object value) => value = new object();

    public static void RefAlias(ref ObjectAlias value) => value = new object();

    public static void RefTwo(ref object first, ref object second)
    {
        first = second;
    }

    public static void OutObject(out object value) => value = new();

    public static void InObject(in object value) => _ = value;

    public static void ByValueObject(object value) => _ = value;

    public static void RefString(ref string value) => value = string.Empty;

    public static void RefGeneric<T>(ref T value) { }
}
