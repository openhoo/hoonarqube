internal unsafe class UnsafeScanner
{
    unsafe int* probe;

    unsafe void Scan(int* seed)
    {
        int local = *seed;
        unsafe
        {
            probe = &local;
        }
    }
}
