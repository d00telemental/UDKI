using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace UDKI.Core.Helpers
{
    public static class ThrowHelper
    {
        [DoesNotReturn]
        public static void ThrowArgumentNullException(string? paramName)
        {
            throw new ArgumentNullException(paramName);
        }

        [DoesNotReturn]
        public static void ThrowArgumentOutOfRangeException(string? paramName)
        {
            throw new ArgumentOutOfRangeException(paramName);
        }

        [DoesNotReturn]
        public static void ThrowDivideByZeroException()
        {
            throw new DivideByZeroException();
        }

        public static void ThrowExceptionIfNull(string? paramName, object? obj)
        {
            if (obj == null)
            {
                throw new ArgumentNullException(paramName);
            }
        }

        [DoesNotReturn]
        public static void ThrowArgumentException(string? paramName, string? message)
        {
            throw new ArgumentException(message, paramName);
        }

        public static void ThrowIfNotInBounds(int index, int length, [CallerArgumentExpression("index")] string? paramName = null)
        {
            //by casting to uint, this also checks if index is negative
            if (unchecked((uint)index >= (uint)length))
            {
                ThrowArgumentOutOfRangeException(paramName);
            }
        }
    }
}
