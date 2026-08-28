public class ParenNest
{
    public int Compute(int total, int left, int right)
    {
        int product = (total * left) + (right * total);
        int grouped = (total + left) * right;
        return product + grouped;
    }
}
