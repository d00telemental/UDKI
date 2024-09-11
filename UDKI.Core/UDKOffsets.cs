namespace UDKI.Core;


/// <summary>
/// Statically provides relative addresses to key parts of <c>UDK.exe</c> binary.
/// </summary>
public static class UDKOffsets
{
    /// <summary><c>UObject::GObjObjects</c></summary>
    public static readonly IntPtr Objects = 0x3678F98;
    /// <summary><c>FName::Names</c></summary>
    public static readonly IntPtr Names = 0x3678F50;
    /// <summary><c>UClass::PrivateStaticClassUClass</c></summary>
    public static readonly IntPtr ClassClass = 0x356D860;

    public static readonly IntPtr FNameInit = 0x268090;
    public static readonly IntPtr StaticFindObject = 0x270520;
    public static readonly IntPtr StaticFindObjectFastInternal = 0x270280;
}
