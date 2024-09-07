using System.Runtime.InteropServices;
using System.Text;

namespace UDKI.Core;


/// <summary>
/// Structure of an Unreal <c>FArray</c> / <c>TArray</c>, compatible with in-memory layout.
/// It is annotated with a "sequential" layout to allow marshalling it via native .NET utilities.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public struct FArray
{
    public IntPtr Allocation;
    public int Count;
    public int Capacity;

    public readonly IntPtr GetItemOffset(int index, int size)
    {
        if (index < 0 || index >= Count)
            throw new ArgumentOutOfRangeException(nameof(index));

        return Allocation + index * size;
    }

    public readonly void Deconstruct(out IntPtr allocation, out int count, out int capacity)
    {
        allocation = Allocation;
        count = Count;
        capacity = Capacity;
    }
}


/// <summary>
/// Structure of an Unreal <c>FName</c>, compatible with in-memory layout.
/// It is annotated with a "sequential" layout to allow marshalling it via native .NET utilities.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 8)]
public struct FName
{
    public int EntryIndex;
    public int NumberPlusOne;
}

/// <summary>
/// Purely managed representation of an Unreal <c>FNameEntry</c>.
/// It is INCOMPATIBLE with in-memory layout, and MUST NOT be marshalled via native .NET utilities.
/// </summary>
/// <see cref="UDKRemote.ReadNameEntry(nint)">For resolving a name entry from a pointer.</see>
/// <see cref="UDKRemote.ReadNameEntry(int)">For resolving a name entry from a name index.</see>
public struct FNameEntry
{
    public ulong Flags;
    public int HashIndex;
    public IntPtr HashNext;
    public string? Text;

    public readonly bool IsNull => Text is null;
}


[UClass("Object", fixedSize: 0x60)]
public class UObject
{
    [UField("ObjectFlags", 0x10)]
    public ulong ObjectFlags;
    [UField("StateFrame", 0x20)]
    public IntPtr StateFrame;
    [UField("Index", 0x38)]
    public int Index;
    [UField("Index", 0x3C)]
    public int NetIndex;
    [UField("Outer", 0x40)]
    public UObject? Outer;
    [UField("Name", 0x48, AsFName = true)]
    public string Name = string.Empty;
    [UField("Class", 0x50)]
    public UClass? Class;
    [UField("ObjectArchetype", 0x58)]
    public UObject? ObjectArchetype;

    public override string ToString()
    {
        StringBuilder builder = new();

        builder.Append(Class!.Name);
        builder.Append(' ');

        if (Outer is not null)
        {
            if (Outer!.Outer is not null)
            {
                if (Outer!.Outer!.Outer is not null)
                {
                    builder.Append(Outer!.Outer!.Outer!.Name);
                    builder.Append('.');
                }

                builder.Append(Outer!.Outer!.Name);
                builder.Append('.');
            }

            builder.Append(Outer!.Name);
            builder.Append('.');
        }

        builder.Append(Name);

        return builder.ToString();
    }
}

[UClass("Field", fixedSize: 0x68)]
public class UField : UObject
{
    [UField("Next", 0x60)]
    public UField? Next;
}

[UClass("Struct", fixedSize: 0xD0)]
public class UStruct : UField
{
    [UField("SuperStruct", 0x78)]
    public UStruct? SuperStruct;
    [UField("Children", 0x80)]
    public UField? Children;
    [UField("PropertiesSize", 0x88)]
    public int PropertiesSize;
}

[UClass("State", fixedSize: 0x124)]
public class UState : UStruct
{
    [UField("ProbeMask", 0xD0)]
    public uint ProbeMask;
    [UField("StateFlags", 0xD4)]
    public uint StateFlags;
    [UField("LabelTableOffset", 0xD8)]
    public uint LabelTableOffset;
}

[UClass("Class", fixedSize: 0x280)]
public class UClass : UState
{
    // ...
}

[UClass("Function", fixedSize: 0x100)]
public class UFunction : UStruct
{
    [UField("FunctionFlags", 0xD0)]
    public uint FunctionFlags;
    [UField("iNative", 0xD4)]
    public ushort iNative;
    [UField("RepOffset", 0xD6)]
    public ushort RepOffset;
    [UField("FriendlyName", 0xD8, AsFName = true)]
    public string FriendlyName = string.Empty;
    [UField("NumParms", 0xE9)]
    public byte NumParms;
    [UField("ParmsSize", 0xEA)]
    public ushort ParmsSize;
    [UField("ReturnValueOffset", 0xEC)]
    public ushort ReturnValueOffset;
    [UField("Func", 0xF8)]
    public IntPtr Func;
}

[UClass("Property", fixedSize: 0xA8)]
public class UProperty : UField
{
    [UField("ArrayDim", 0x68)]
    public int ArrayDim;
    [UField("ElementSize", 0x6C)]
    public int ElementSize;
    [UField("PropertyFlags", 0x70)]
    public ulong PropertyFlags;
    [UField("RepOffset", 0x78)]
    public ushort RepOffset;
    [UField("RepIndex", 0x7A)]
    public ushort RepIndex;
    [UField("Category", 0x7C, AsFName = true)]
    public string Category = string.Empty;
    [UField("ArraySizeEnum", 0x84)]
    public IntPtr ArraySizeEnum;
    [UField("Offset", 0x8C)]
    public int Offset;
    [UField("PropertyLinkNext", 0x90)]
    public UProperty? PropertyLinkNext;
    [UField("ConstructorLinkNext", 0x98)]
    public UProperty? ConstructorLinkNext;
    [UField("NextRef", 0xA0)]
    public UProperty? NextRef;
}

[UClass("ByteProperty", fixedSize: 0xB0)]
public class UByteProperty : UProperty
{
    [UField("Enum", 0xA8)]
    public IntPtr Enum;
}

[UClass("IntProperty", fixedSize: 0xA8)]
public class UIntProperty : UProperty
{
    // ...
}

[UClass("FloatProperty", fixedSize: 0xA8)]
public class UFloatProperty : UProperty
{
    // ...
}

[UClass("BoolProperty", fixedSize: 0xAC)]
public class UBoolProperty : UProperty
{
    [UField("BitMask", 0xA8)]
    public uint BitMask;
}

[UClass("StrProperty", fixedSize: 0xA8)]
public class UStrProperty : UProperty
{
    // ...
}

[UClass("NameProperty", fixedSize: 0xA8)]
public class UNameProperty : UProperty
{
    // ...
}

[UClass("DelegateProperty", fixedSize: 0xB8)]
public class UDelegateProperty : UProperty
{
    [UField("Function", 0xA8)]
    public UFunction? Function;
    [UField("Function", 0xB0)]
    public UFunction? SourceDelegate;
}

[UClass("ObjectProperty", fixedSize: 0xB0)]
public class UObjectProperty : UProperty
{
    [UField("PropertyClass", 0xA8)]
    public UClass? PropertyClass;
}

[UClass("ClassProperty", fixedSize: 0xB8)]
public class UClassProperty : UObjectProperty
{
    [UField("MetaClass", 0xB0)]
    public UClass? MetaClass;
}

[UClass("InterfaceProperty", fixedSize: 0xB0)]
public class UInterfaceProperty : UProperty
{
    [UField("InterfaceClass", 0xA8)]
    public UClass? InterfaceClass;
}

[UClass("StructProperty", fixedSize: 0xB0)]
public class UStructProperty : UProperty
{
    [UField("Struct", 0xA8)]
    public UStruct? Struct;
}

[UClass("ArrayProperty", fixedSize: 0xB0)]
public class UArrayProperty : UProperty
{
    [UField("Inner", 0xA8)]
    public UProperty? Inner;
}

[UClass("MapProperty", fixedSize: 0xB8)]
public class UMapProperty : UProperty
{
    [UField("Key", 0xA8)]
    public UProperty? Key;
    [UField("Value", 0xB0)]
    public UProperty? Value;
}


// TODO: UConst, UEnum, UScriptStruct
