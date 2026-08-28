// S4211 good: member transparency agrees with its containing type or is explicit.
using System.Security;

namespace Oracle.S4211
{
    [SecurityCritical]
    internal sealed class CriticalGood
    {
        [SecurityCritical]
        public int Danger() => 1;
    }

    [SecuritySafeCritical]
    internal sealed class SafeCriticalGood
    {
        [SecuritySafeCritical]
        public int Bridge() => 2;
    }

    internal sealed class TransparentGood
    {
        [SecurityCritical]
        public int Plain() => 3;
    }
}
