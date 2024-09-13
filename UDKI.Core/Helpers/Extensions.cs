using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UDKI.Core.Helpers
{
    public static class Extensions
    {
        public static int Align(this int value, int align)
        {
            if (value == 0)
            {
                return value;
            }

            return value + ((align - (value % align)) % align);
        }
    }
}
