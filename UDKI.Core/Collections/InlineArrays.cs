using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace UDKI.Core.Collections
{
    [InlineArray(4)]
    public struct Fixed4<T>
    {
        private T _element0;

        public int Length => 4;

        public Span<T> AsSpan()
        {
            return MemoryMarshal.CreateSpan(ref _element0, Length);
        }
    }
}
