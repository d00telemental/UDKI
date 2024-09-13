using System.Buffers.Binary;
using System.Data;
using System.Dynamic;
using System.Runtime.InteropServices;
using System.Text;
using UDKI.Core.Collections;

namespace UDKI.Core;


#region Core structs.

/// <summary>
/// Structure of an Unreal <c>TMap</c>, compatible with in-memory layout.
/// It is annotated with a "sequential" layout to allow marshalling it via native .NET utilities.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 4, Size = 72)]
public struct TMap
{
    //TSparseArray
    public FArray Data;
    public BitArray AllocationFlags;
    public int FirstFreeIndex;
    public int NumFreeIndices;
    //TSet
    public int InlineHash;
    public IntPtr Hash;
    public int HashSize;

    [StructLayout(LayoutKind.Sequential, Pack = 4, Size = 32)]
    public struct BitArray
    {
        public Fixed4<int> InlineData;
        public IntPtr IndirectData;
        public int NumBits;
        public int MaxBits;
    }
}

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

    public FArray()
    {
        // ...
    }

    public FArray(ReadOnlySpan<byte> arrayView)
    {
        if (arrayView.Length != 16)
            throw new ArgumentException("array view too short", nameof(arrayView));

        Allocation = BinaryPrimitives.ReadIntPtrLittleEndian(arrayView[0..8]);
        Count = BinaryPrimitives.ReadInt32LittleEndian(arrayView[8..12]);
        Capacity = BinaryPrimitives.ReadInt32LittleEndian(arrayView[12..16]);
    }

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

    public FName()
    {
        // ...
    }

    public FName(ReadOnlySpan<byte> view)
    {
        if (view.Length < 8)
            throw new ArgumentException("view too short", nameof(view));

        EntryIndex = BinaryPrimitives.ReadInt32LittleEndian(view[0..4]);
        NumberPlusOne = BinaryPrimitives.ReadInt32LittleEndian(view[4..8]);
    }
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

    public FNameEntry()
    {
        // ...
    }

    public FNameEntry(ReadOnlySpan<byte> view)
    {
        if (view.Length < 20)
            throw new ArgumentException("view too short", nameof(view));

        Flags = BinaryPrimitives.ReadUInt64LittleEndian(view[0..8]);
        HashIndex = BinaryPrimitives.ReadInt32LittleEndian(view[8..12]);
        HashNext = BinaryPrimitives.ReadIntPtrLittleEndian(view[12..20]);
    }
}

/// <summary>
/// Structure of an Unreal <c>FScriptDelegate</c>.
/// It is INCOMPATIBLE with in-memory layout, and MUST NOT be marshalled via native .NET utilities.
/// </summary>
public struct FScriptDelegate
{
    public UObject? Object = null;
    public string FunctionName = string.Empty;

    // This comes from UDelegateProperty, not serialized data.
    public UFunction? StaticFunction = null;

    public FScriptDelegate()
    {
        // ...
    }
}

/// <summary>
/// Structure of an Unreal <c>FScriptInterface</c>.
/// It is INCOMPATIBLE with in-memory layout, and MUST NOT be marshalled via native .NET utilities.
/// </summary>
public struct FScriptInterface
{
    public UObject? Object = null;
    public IntPtr Interface = IntPtr.Zero;

    // This comes from UInterfaceProperty, not serialized data.
    public UClass? StaticInterfaceClass = null;

    public FScriptInterface()
    {
        // ...
    }
}

#endregion


#region Core enumerations.

[Flags]
public enum EObjectFlags : ulong
{
    InSingularFunc = 0x0000000000000002,
    StateChanged = 0x0000000000000004,
    DebugPostLoad = 0x0000000000000008,
    DebugSerialize = 0x0000000000000010,
    DebugFinishDestroyed = 0x0000000000000020,
    EditorSelected = 0x0000000000000040,
    ZombieComponent = 0x0000000000000080,
    Protected = 0x0000000000000100,
    ClassDefaultObject = 0x0000000000000200,
    ArchetypeObject = 0x0000000000000400,
    ForceTagExport = 0x0000000000000800,
    TokenStreamAssembled = 0x0000000000001000,
    MisalignedObject = 0x0000000000002000,
    RootSet = 0x0000000000004000,
    BeginDestroy = 0x0000000000008000,
    FinishDestroy = 0x0000000000010000,
    DebugBeginDestroyed = 0x0000000000020000,
    MarkedByCooker = 0x0000000000040000,
    LocalizedResource = 0x0000000000080000,
    InitializedProperties = 0x0000000000100000,
    PendingFieldPatches = 0x0000000000200000,
    CrossLevelReferenced = 0x0000000000400000,
    Saved = 0x0000000080000000,
    Transactional = 0x0000000100000000,
    Unreachable = 0x0000000200000000,
    Public = 0x0000000400000000,
    TagImport = 0x0000000800000000,
    TagExport = 0x0000001000000000,
    Obsolete = 0x0000002000000000,
    TagGarbage = 0x0000004000000000,
    DisregardForGC = 0x0000008000000000,
    PerObjectLocalized = 0x0000010000000000,
    NeedLoading = 0x0000020000000000,
    AsyncLoading = 0x0000040000000000,
    Suppress = 0x0000100000000000,
    InEndState = 0x0000200000000000,
    Transient = 0x0000400000000000,
    Cooked = 0x0000800000000000,
    LoadForClient = 0x0001000000000000,
    LoadForServer = 0x0002000000000000,
    LoadForEdit = 0x0004000000000000,
    Standalone = 0x0008000000000000,
    NotForClient = 0x0010000000000000,
    NotForServer = 0x0020000000000000,
    NotForEdit = 0x0040000000000000,
    NeedPostLoad = 0x0100000000000000,
    WithStack = 0x0200000000000000,
    Native = 0x0400000000000000,
    Marked = 0x0800000000000000,
    ErrorShutdown = 0x1000000000000000,
    PendingKill = 0x2000000000000000,
    CookedStartupObject = 0x8000000000000000,
}

[Flags]
public enum EClassFlags : uint
{
    None = 0x00000000,
    Abstract = 0x00000001,
    Compiled = 0x00000002,
    Config = 0x00000004,
    Transient = 0x00000008,
    Parsed = 0x00000010,
    Localized = 0x00000020,
    SafeReplace = 0x00000040,
    Native = 0x00000080,
    NoExport = 0x00000100,
    Placeable = 0x00000200,
    PerObjectConfig = 0x00000400,
    NativeReplication = 0x00000800,
    EditInlineNew = 0x00001000,
    CollapseCategories = 0x00002000,
    Interface = 0x00004000,

    IsProperty = 0x00008000,
    IsObjectProperty = 0x00010000,
    IsBoolProperty = 0x00020000,
    IsState = 0x00040000,
    IsFunction = 0x00080000,
    IsStructProperty = 0x00100000,

    HasInstancedProperties = 0x00200000,
    NeedsDefaultProperties = 0x00400000,
    Hidden = 0x01000000,
    Deprecated = 0x02000000,
    HideDropDown = 0x04000000,
    Exported = 0x08000000,
    Intrinsic = 0x10000000,
    NativeOnly = 0x20000000,
    PerObjectLocalized = 0x40000000,
    HasCrossLevelReferences = 0x80000000,
}

[Flags]
public enum EPropertyFlags : ulong
{
    Edit = 0x0000000000000001,
    Const = 0x0000000000000002,
    Input = 0x0000000000000004,
    ExportObject = 0x0000000000000008,
    OptionalParam = 0x0000000000000010,
    Net = 0x0000000000000020,
    EditFixedSize = 0x0000000000000040,
    Param = 0x0000000000000080,
    OutParam = 0x0000000000000100,
    SkipParam = 0x0000000000000200,
    ReturnParam = 0x0000000000000400,
    CoerceParam = 0x0000000000000800,
    Native = 0x0000000000001000,
    Transient = 0x0000000000002000,
    Config = 0x0000000000004000,
    Localized = 0x0000000000008000,
    EditConst = 0x0000000000020000,
    GlobalConfig = 0x0000000000040000,
    Component = 0x0000000000080000,
    AlwaysInit = 0x0000000000100000,
    DuplicateTransient = 0x0000000000200000,
    NeedsCtorLink = 0x0000000000400000,
    NoExport = 0x0000000000800000,
    NoImport = 0x0000000001000000,
    NoClear = 0x0000000002000000,
    EditInline = 0x0000000004000000,
    EditInlineUse = 0x0000000010000000,
    Deprecated = 0x0000000020000000,
    DataBinding = 0x0000000040000000,
    SerializeText = 0x0000000080000000,
    RepNotify = 0x0000000100000000,
    Interp = 0x0000000200000000,
    NonTransact = 0x0000000400000000,
    EditorOnly = 0x0000000800000000,
    NotForConsole = 0x0000001000000000,
    RepRetry = 0x0000002000000000,
    PrivateWrite = 0x0000004000000000,
    ProtectedWrite = 0x0000008000000000,
    ArchetypeProperty = 0x0000010000000000,
    EditorHide = 0x0000020000000000,
    EditorTextBox = 0x0000040000000000,
    CrossLevelPassive = 0x0000100000000000,
    CrossLevelActive = 0x0000200000000000,
}

[Flags]
public enum EStructFlags : uint
{
    Native = 0x00000001,
    Export = 0x00000002,
    HasComponents = 0x00000004,
    Transient = 0x00000008,
    Atomic = 0x00000010,
    Immutable = 0x00000020,
    StrictConfig = 0x00000040,
    ImmutableWhenCooked = 0x00000080,
    AtomicWhenCooked = 0x00000100,
}

[Flags]
public enum EStateFlags : uint
{
    Editable = 0x00000001,
    Automatic = 0x00000002,
    Simulated = 0x00000004,
    HasLocals = 0x00000008,
}

[Flags]
public enum EFunctionFlags : uint
{
    Final = 0x00000001,
    Defined = 0x00000002,
    Iterator = 0x00000004,
    Latent = 0x00000008,
    PrefixOperator = 0x00000010,
    Singular = 0x00000020,
    Net = 0x00000040,
    NetReliable = 0x00000080,
    Simulated = 0x00000100,
    Exec = 0x00000200,
    Native = 0x00000400,
    Event = 0x00000800,
    Operator = 0x00001000,
    Static = 0x00002000,
    HasOptionalParams = 0x00004000,
    Const = 0x00008000,
    Public = 0x00020000,
    Private = 0x00040000,
    Protected = 0x00080000,
    Delegate = 0x00100000,
    NetServer = 0x00200000,
    HasOutParams = 0x00400000,
    HasDefaults = 0x00800000,
    NetClient = 0x01000000,
    DllImport = 0x02000000,
}

#endregion


#region Miscellaneous types.

[UClass("FFrame", fixedSize: 0x44)]
public class FFrame
{
    [UField("VfTableObject", 0x00)]
    public IntPtr VfTableObject;
    [UField("bAllowSuppression", 0x08)]
    public int bAllowSuppression;
    [UField("bSuppressEventTag", 0x0C)]
    public int bSuppressEventTag;
    [UField("bAutoEmitLineTerminator", 0x10)]
    public int bAutoEmitLineTerminator;
    [UField("Node", 0x14)]
    public UStruct? Node;
    [UField("Object", 0x1C)]
    public UObject? Object;
    [UField("Code", 0x24)]
    public IntPtr Code;
    [UField("Locals", 0x2C)]
    public IntPtr Locals;
    [UField("PreviousFrame", 0x34)]
    public FStackFrame? PreviousFrame;
    [UField("OutParams", 0x3C)]
    public IntPtr OutParams;
}

[UClass("FStackFrame", fixedSize: 0x6C)]
public class FStackFrame : FFrame
{
    [UField("StateNode", 0x44)]
    public UState? StateNode;
    [UField("ProbeMask", 0x4C)]
    public uint ProbeMask;
    [UField("LatentAction", 0x50)]
    public ushort LatentAction;
    [UField("bContinuedState", 0x52)]
    public byte bContinuedState;
    // 0x54: StateStack
    [UField("LocalVarsOwner", 0x64)]
    public IntPtr LocalVarsOwner;
}

#endregion


#region ScriptStruct implementation.

/// <summary>Stores and provides dynamic access to properties of a serialized <see cref="UScriptStruct"/>.</summary>
/// <remarks>Make sure to assign values of this type to <c>dynamic</c> variables to be able to use dynamic member lookup.</remarks>
public sealed class DynamicScriptStruct : DynamicObject
{
    internal Dictionary<string, object?> _fields = [];
    internal UScriptStruct? _struct = null;

    internal DynamicScriptStruct() { }

    public UScriptStruct Struct => _struct!;

    public override bool TryGetMember(GetMemberBinder binder, out object? result)
    {
        if (_fields.TryGetValue(binder.Name, out result)) return true;
        throw new KeyNotFoundException($"can't find member '{binder.Name}' in {_struct}");
    }

    public override bool TrySetMember(SetMemberBinder binder, object? value)
        => throw new InvalidOperationException("ScriptStruct members are read-only");

    public override string ToString()
    {
        StringBuilder stringBuilder = new();

        stringBuilder.Append(_struct?.Name);
        stringBuilder.Append('(');

        foreach ((string name, object? value) in _fields)
        {
            stringBuilder.Append(name);
            stringBuilder.Append('=');
            stringBuilder.Append(value?.ToString() ?? "(null)");
            stringBuilder.Append(", ");
        }

        if (_fields.Count != 0)
        {
            // Chop off the trailing comma.
            stringBuilder.Remove(stringBuilder.Length - 2, 2);
        }

        stringBuilder.Append(')');

        return stringBuilder.ToString();
    }
}

#endregion


#region UObject hierarchy.

[UClass("Object", fixedSize: 0x60)]
public class UObject
{
    protected internal IntPtr _sourcePointer;
    protected internal WeakReference<UDKRemote>? _sourceRemote;
    protected internal WeakReference<UDKGeneration>? _sourceGeneration;
    protected internal byte[]? _cachedBytes;

    [UField("VfTableObject", 0x00)]
    public IntPtr VfTableObject;
    [UField("ObjectFlags", 0x10)]
    public EObjectFlags ObjectFlags;
    [UField("StateFrame", 0x20)]
    public FStackFrame? StateFrame;
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

    public IEnumerable<UObject> GetOuterChain()
    {
        UObject? iterOuter = Outer;
        while (iterOuter is not null)
        {
            yield return iterOuter;
            iterOuter = iterOuter.Outer;
        }
    }

    public UObject GetOutermost() => GetOuterChain().Last();

    public UProperty GetProperty(string name)
    {
        return Class?.GetProperties(true).FirstOrDefault(p => p.Name == name)
            ?? throw new KeyNotFoundException($"property '{name}' is not present on '{this}'");
    }

    public object? GetPropertyValue(string name, Type? checkType = null)
    {
        if (!_sourceRemote!.TryGetTarget(out UDKRemote? sourceRemote))
            throw new InvalidOperationException();

        if (!_sourceGeneration!.TryGetTarget(out UDKGeneration? sourceGeneration))
            throw new InvalidOperationException();

        UProperty property = GetProperty(name);
        _cachedBytes ??= sourceRemote.ReadObjectBytes(this);
        return sourceRemote.ReadPropertyInternal(_cachedBytes, checkType, property, sourceGeneration);
    }

    public T GetPropertyValue<T>(string name) => (T)GetPropertyValue(name, typeof(T))!;

    public void ForEachProperty(bool bWithSuper, Func<UProperty, bool> propertyCallback)
    {
        foreach (var property in Class!.GetProperties(bWithSuper))
        {
            if (!propertyCallback(property))
                break;
        }
    }

    public void ForEachPropertyValue(bool bWithSuper, Func<UProperty, object?, bool> propertyCallback)
    {
        if (!_sourceRemote!.TryGetTarget(out UDKRemote? sourceRemote))
            throw new InvalidOperationException();

        if (!_sourceGeneration!.TryGetTarget(out UDKGeneration? sourceGeneration))
            throw new InvalidOperationException();

        _cachedBytes ??= sourceRemote.ReadObjectBytes(this);

        foreach (var property in Class!.GetProperties(bWithSuper))
        {
            var value = sourceRemote.ReadPropertyInternal(_cachedBytes, null, property, sourceGeneration);
            if (!propertyCallback(property, value))
                break;
        }
    }

    public UFunction? FindFunction(string funcName, bool bGlobalOnly = false)
    {
        if (StateFrame?.StateNode is not null && !bGlobalOnly)
        {
            var stateFunction = StateFrame.StateNode
                .GetFunctions(bWithSuper: true)
                .FirstOrDefault(func => func.Name == funcName);

            if (stateFunction is not null)
                return stateFunction;
        }

        if (Class is not null)
        {
            var classFunction = Class
                .GetFunctions(bWithSuper: true)
                .FirstOrDefault(func => func.Name == funcName);

            if (classFunction is not null)
                return classFunction;
        }

        return null;
    }

    public UFunction FindFunctionChecked(string funcName, bool bGlobalOnly = false)
    {
        return FindFunction(funcName, bGlobalOnly) switch
        {
            var function when function is not null => function!,
            _ => throw new KeyNotFoundException($"failed to find function '{funcName}' in '{this}'"),
        };
    }

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
                    if (Outer!.Outer!.Outer!.Outer is not null)
                    {
                        builder.Append(Outer!.Outer!.Outer!.Outer!.Name);
                        builder.Append('.');
                    }

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

    public IEnumerable<UField> GetNextChain()
    {
        UField? iterNext = Next;
        while (iterNext is not null)
        {
            yield return iterNext;
            iterNext = iterNext.Next;
        }
    }
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

    public IEnumerable<UStruct> GetSuperChain(bool bWithSelf = false)
    {
        if (bWithSelf) yield return this;

        UStruct? iterSuper = SuperStruct;
        while (iterSuper is not null)
        {
            yield return iterSuper;
            iterSuper = iterSuper.SuperStruct;
        }
    }

    public IEnumerable<UField> GetChildren(bool bWithSuper = false)
    {
        if (Children is not null)
        {
            yield return Children;
            foreach (var child in Children.GetNextChain())
                yield return child;
        }

        if (bWithSuper)
        {
            foreach (var super in GetSuperChain())
                foreach (var child in super.GetChildren())
                    yield return child;
        }
    }

    public IEnumerable<UFunction> GetFunctions(bool bWithSuper = false)
        => GetChildren(bWithSuper)
            .Select(child => child as UFunction)
            .Where(func => func is not null)
            .Select(func => func!);

    public IEnumerable<UProperty> GetProperties(bool bWithSuper = false)
        => GetChildren(bWithSuper)
            .Select(child => child as UProperty)
            .Where(prop => prop is not null)
            .Select(prop => prop!);
}

[UClass("State", fixedSize: 0x124)]
public class UState : UStruct
{
    [UField("ProbeMask", 0xD0)]
    public uint ProbeMask;
    [UField("StateFlags", 0xD4)]
    public EStateFlags StateFlags;
    [UField("LabelTableOffset", 0xD8)]
    public uint LabelTableOffset;
    [UField("FuncMap", 0xDC, MapKeyAsFName = true)]
    public UMap<string, UFunction>? FuncMap;
}

[UClass("Class", fixedSize: 0x280)]
public class UClass : UState
{
    [UField("ClassFlags", 0x124)]
    public EClassFlags ClassFlags;
    [UField("ClassCastFlags", 0x128)]
    public uint ClassCastFlags;
    [UField("ClassUnique", 0x12C)]
    public uint ClassUnique;
    [UField("ClassWithin", 0x130)]
    public UClass? ClassWithin;
    [UField("ClassConfigName", 0x138, AsFName = true)]
    public string ClassConfigName = string.Empty;
    [UField("NetFields", 0x150)]
    public UField[]? NetFields;
    [UField("ClassHeaderFilename", 0x1C4)]
    public string ClassHeaderFilename = string.Empty;
    [UField("ClassDefaultObject", 0x1E4)]
    public UObject? ClassDefaultObject;
    [UField("ClassConstructor", 0x1EC)]
    public IntPtr ClassConstructor;
    [UField("ClassStaticConstructor", 0x1F4)]
    public IntPtr ClassStaticConstructor;
    [UField("ClassStaticInitializer", 0x1FC)]
    public IntPtr ClassStaticInitializer;
    [UField("DefaultPropText", 0x25C)]
    public string DefaultPropText = string.Empty;

    public IEnumerable<UState> GetStates(bool bWithSuper = false)
        => GetChildren(bWithSuper)
            .Select(child => child as UState)
            .Where(state => state is not null)
            .Select(state => state!);
}

[UClass("Function", fixedSize: 0x100)]
public class UFunction : UStruct
{
    [UField("FunctionFlags", 0xD0)]
    public EFunctionFlags FunctionFlags;
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

    public IEnumerable<UProperty> GetParams()
        => GetProperties(false).Where(prop => prop.PropertyFlags.HasFlag(EPropertyFlags.Param));
}

[UClass("ScriptStruct", fixedSize:0xF4)]
public class UScriptStruct : UStruct
{
    [UField("DefaultStructPropText", 0xD0)]
    public string DefaultStructPropText = string.Empty;
    [UField("StructFlags", 0xE0)]
    public EStructFlags StructFlags;
    [UField("StructDefaults", 0xE4)]
    public byte[]? StructDefaults;
}

[UClass("Const", fixedSize: 0x78)]
public class UConst : UField
{
    [UField("Value", 0x68)]
    public string Value = string.Empty;
}

[UClass("Enum", fixedSize: 0x78)]
public class UEnum : UField
{
    [UField("Names", 0x68, AsFName = true)]
    public string[]? Names;
}

[UClass("Property", fixedSize: 0xA8)]
public class UProperty : UField
{
    [UField("ArrayDim", 0x68)]
    public int ArrayDim;
    [UField("ElementSize", 0x6C)]
    public int ElementSize;
    [UField("PropertyFlags", 0x70)]
    public EPropertyFlags PropertyFlags;
    [UField("RepOffset", 0x78)]
    public ushort RepOffset;
    [UField("RepIndex", 0x7A)]
    public ushort RepIndex;
    [UField("Category", 0x7C, AsFName = true)]
    public string Category = string.Empty;
    [UField("ArraySizeEnum", 0x84)]
    public UEnum? ArraySizeEnum;
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
    public UEnum? Enum;
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

[UClass("ComponentProperty", fixedSize: 0xB0)]
public class UComponentProperty : UObjectProperty
{
    // ...
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
    public UScriptStruct? Struct;
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

#endregion
