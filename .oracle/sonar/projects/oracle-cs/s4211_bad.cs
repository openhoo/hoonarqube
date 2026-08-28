// S4211 bad: member transparency conflicts with its containing type.
using System.Security;

namespace Oracle.S4211
{
    [SecuritySafeCritical]
    public class SafeCriticalContainer
    {
        [SecurityCritical] // S4211
        public void CriticalMember()
        {
        }
    }

    [SecurityCritical]
    public class CriticalContainer
    {
        [SecuritySafeCritical] // S4211
        public void SafeCriticalMember()
        {
        }
    }
}
