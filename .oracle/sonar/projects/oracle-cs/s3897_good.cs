public class Meter : System.IEquatable<Meter>
{
    public bool Equals(Meter other)
    {
        return Level == other.Level;
    }

    public override bool Equals(object obj)
    {
        return obj is Meter other && Equals(other);
    }

    public int Level;
}
