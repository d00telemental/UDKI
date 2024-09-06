namespace UDKI.Core;


/// <summary>
/// Statically provides relative addresses to key parts of <c>UDK.exe</c> binary.
/// </summary>
public static class UDKOffsets
{
    public static readonly IntPtr GObjObjects = 0x3678F98;
    public static readonly IntPtr Names = 0x3678F50;
}
