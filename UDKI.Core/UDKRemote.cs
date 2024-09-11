using System.Buffers;
using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;


namespace UDKI.Core;


/// <summary>
/// Connection to a remote UDK for instrumentation.
/// </summary>
public sealed class UDKRemote : IDisposable
{
    internal record struct RefQueueItem(object Outer, FieldInfo Field, Type Type, nint Address, int? ArrayIndex);

    readonly ProcessHandle _process;
    readonly UDKGeneration _generation;
    readonly BufferedStream _stream;

    readonly bool _disposeProcessHandle;

    readonly Dictionary<Type, UClassAttribute> _classAttributeCache;
    readonly Dictionary<Type, (FieldInfo, UFieldAttribute)[]> _fieldArrayCache;

    readonly IntPtr _inputBufferAllocation;
    readonly byte[] _inputBufferZeros;
    readonly IntPtr _outputBufferAllocation;
    readonly byte[] _outputBufferZeros;
    readonly IntPtr _paramStructAllocation;

    readonly ArrayPool<byte> _objectMemoryPool;

    readonly FieldInfo _sourcePointerField;
    readonly FieldInfo _sourceRemoteField;
    readonly FieldInfo _sourceGenerationField;

    readonly IntPtr _addressObjects;
    readonly IntPtr _addressNames;
    readonly IntPtr _addressClassClass;
    readonly IntPtr _addressFNameInit;
    readonly IntPtr _addressStaticFindObject;
    readonly IntPtr _addressStaticFindObjectFastInternal;

    /// <summary>Number of bytes allocated for internal parameters buffer.</summary>
    public const int InputBufferSize = 1024;
    /// <summary>Number of bytes allocated for internal return value buffer.</summary>
    public const int OutputBufferSize = 1024;

    /// <summary>Number of bytes used for internal read-ahead buffer.</summary>
    /// <remarks>Using a really small buffer to reduce risk of running into a protected region.</remarks>
    public const int StreamBufferSize = 128;


    UDKRemote(ProcessHandle processHandle, bool bDisposeHandle)
    {
        _process = processHandle;
        _generation = new(_process, freezeThreads: false);
        _stream = new(new ProcessMemoryStream(_process), StreamBufferSize);

        _disposeProcessHandle = bDisposeHandle;

        _classAttributeCache = [];
        _fieldArrayCache = [];

        _inputBufferAllocation = _process.Alloc(InputBufferSize);
        _inputBufferZeros = new byte[InputBufferSize];
        Array.Fill<byte>(_inputBufferZeros, 0xCC);

        _outputBufferAllocation = _process.Alloc(OutputBufferSize);
        _outputBufferZeros = new byte[OutputBufferSize];
        Array.Fill<byte>(_outputBufferZeros, 0xDD);

        Span<byte> paramStructBytes = stackalloc byte[16];
        BinaryPrimitives.WriteIntPtrLittleEndian(paramStructBytes[0..8], _inputBufferAllocation);
        BinaryPrimitives.WriteIntPtrLittleEndian(paramStructBytes[8..16], _outputBufferAllocation);

        _paramStructAllocation = _process.Alloc(16);
        _process.WriteMemoryChecked(_paramStructAllocation, paramStructBytes);

        _objectMemoryPool = ArrayPool<byte>.Create();

        _sourcePointerField = typeof(UObject).GetField("_sourcePointer", BindingFlags.NonPublic | BindingFlags.Instance)!;
        _sourceRemoteField = typeof(UObject).GetField("_sourceRemote", BindingFlags.NonPublic | BindingFlags.Instance)!;
        _sourceGenerationField = typeof(UObject).GetField("_sourceGeneration", BindingFlags.NonPublic | BindingFlags.Instance)!;

        _addressObjects = ResolveOffset(UDKOffsets.Objects);
        _addressNames = ResolveOffset(UDKOffsets.Names);
        _addressClassClass = ReadPointer(ResolveOffset(UDKOffsets.ClassClass));
        _addressFNameInit = ResolveOffset(UDKOffsets.FNameInit);
        _addressStaticFindObject = ResolveOffset(UDKOffsets.StaticFindObject);
        _addressStaticFindObjectFastInternal = ResolveOffset(UDKOffsets.StaticFindObjectFastInternal);
    }

    public UDKRemote() : this(ProcessHandle.FindUDK(), true) { }
    public UDKRemote(ProcessHandle process) : this(process, false) { }


    /// <summary>
    /// Resolves a memory offset relative to the main module base into an absolute pointer.
    /// </summary>
    public IntPtr ResolveOffset(IntPtr offset) => _process.MainModule.BaseAddress + offset;

    /// <summary>
    /// Constructs a new access generation, optionally freezing remote threads for the duration of its lifetime.
    /// </summary>
    public UDKGeneration CreateGeneration(bool freezeThreads = false) => new(_process, freezeThreads);


    #region IDisposable implementation.

    private bool _disposedValue;

    private void Dispose(bool disposing)
    {
        if (!_disposedValue)
        {
            _process.Free(_inputBufferAllocation);
            _process.Free(_outputBufferAllocation);
            _process.Free(_paramStructAllocation);

            if (disposing)
            {
                _generation.Dispose();
                _stream.Dispose();

                if (_disposeProcessHandle)
                    _process.Dispose();
            }

            _disposedValue = true;
        }
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    #endregion


    #region Code execution.

    static int AlignToMultiple(int value, int align) => (value + align - 1) / align * align;

    static void WriteAssemblyPrologue(Assembler asm)
    {
        asm.mov(rbp, rsp);
        asm.sub(rsp, 32);
        asm.and(rsp, -15);
    }

    static void WriteAssemblyEpilogue(Assembler asm)
    {
        asm.xor(rax, rax);
        asm.mov(rsp, rbp);
        asm.ret();
    }

    static int EstimateAssemblySize(Assembler asm)
    {
        using var stream = new MemoryStream();
        asm.Assemble(new StreamCodeWriter(stream), 0);
        return AlignToMultiple((int)stream.Length, 256);
    }

    static byte[] BuildAssembly(Assembler asm, ulong rip)
    {
        using var stream = new MemoryStream();
        asm.Assemble(new StreamCodeWriter(stream), rip);
        return stream.ToArray();
    }

    /// <summary>Executes a manually-constructed piece of assembly code in a new remote thread, without input or output data.</summary>
    /// <param name="writeAssemblyBody">Callback that generates body of code to execute.</param>
    public void Execute(Action<Assembler> writeAssemblyBody) => Execute([], [], writeAssemblyBody);

    /// <summary>Executes a manually-constructed piece of assembly code in a new remote thread.</summary>
    /// <param name="inputBuffer">Buffer which contains serialized parameters to copy into internal parameter buffer.</param>
    /// <param name="outputBuffer">Buffer which will receive a copy of data from the internal return value buffer.</param>
    /// <param name="writeAssemblyBody">Callback that generates body of code to execute.</param>
    public void Execute(ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer, Action<Assembler> writeAssemblyBody)
    {
        if (inputBuffer.Length >= InputBufferSize) throw new ArgumentException("input buffer too large", nameof(inputBuffer));
        if (outputBuffer.Length >= OutputBufferSize) throw new ArgumentException("output buffer too large", nameof(outputBuffer));

        _process.WriteMemoryChecked(_inputBufferAllocation, _inputBufferZeros);
        _process.WriteMemoryChecked(_outputBufferAllocation, _outputBufferZeros);


        if (!inputBuffer.IsEmpty)
        {
            // Copy input arguments to the process-side input buffer.
            _process.WriteMemoryChecked(_inputBufferAllocation, inputBuffer);
        }


        Assembler localAssembler = new(64);

        WriteAssemblyPrologue(localAssembler);
        writeAssemblyBody(localAssembler);
        WriteAssemblyEpilogue(localAssembler);

        var alignedLength = (ulong)EstimateAssemblySize(localAssembler);
        var allocatedBuffer = _process.Alloc(alignedLength);

        try
        {
            var assembledBinary = BuildAssembly(localAssembler, (ulong)allocatedBuffer);

            _process.WriteMemoryChecked(allocatedBuffer, assembledBinary);
            _process.ProtectExecutable(allocatedBuffer, alignedLength);

            var execThread = _process.CreateThread(allocatedBuffer, _paramStructAllocation, out _);

            Windows.WaitForSingleObject(execThread);
            Windows.CloseHandle(execThread);
        }
        finally
        {
            _process.Free(allocatedBuffer);
        }


        if (!outputBuffer.IsEmpty)
        {
            // Extract bytes from the process-side output buffer.
            _process.ReadMemoryChecked(_outputBufferAllocation, outputBuffer);
        }
    }

    #endregion


    #region Allocation and search.

    /// <summary>Looks up or inserts an <c>FName</c> by string.</summary>
    /// <param name="value">String value.</param>
    /// <param name="bSplitName">Whether to split number part from string <c>value</c>.</param>
    /// <returns>An engine-provided <c>FName</c> instance.</returns>
    public FName InitName(string value, bool bSplitName = true)
    {
        var valueBytes = Encoding.Unicode.GetBytes(value);

        byte[] inputBuffer = new byte[valueBytes.Length + 2];
        Span<byte> outputBuffer = stackalloc byte[FNameSize];

        {
            Array.Fill<byte>(inputBuffer, 0x00);
            Array.Copy(valueBytes, inputBuffer, valueBytes.Length);
        }

        Execute(inputBuffer, outputBuffer, (asm) =>
        {
            asm.mov(r12, __qword_ptr[rcx]);
            asm.mov(r13, __qword_ptr[rcx + 8]);

            asm.sub(rsp, 0x28);

            asm.mov(rcx, r13);      // Output buffer as (this) pointer.
            asm.mov(rdx, r12);      // Input buffer pointer as cw-string.
            asm.mov(r8d, 0);        // Default instance number (0).
            asm.mov(r9d, 1);        // Lookup mode (FNAME_Add).
            asm.mov(__dword_ptr[rsp + 0x20], bSplitName ? 1 : 0);

            asm.mov(rax, _addressFNameInit);
            asm.call(rax);          // Call FName::Init.
        });

        return new FName(outputBuffer);
    }

    /// <summary>Searches for a class by name.</summary>
    /// <param name="className">Unscoped class name (without outer chain or class).</param>
    /// <param name="bAllowDerived">Whether to allow subclasses.</param>
    /// <returns>Pointer to a class object.</returns>
    public IntPtr FindClass(string className, bool bAllowDerived = true)
    {
        FName objectName = InitName(className, false);
        return FindObjectFastInternal(_addressClassClass, objectName, bAllowDerived, 0);
    }

    /// <summary>Searches for a class instance by name and deserializes it.</summary>
    /// <param name="className">Unscoped class name (without outer chain or class).</param>
    /// <param name="generation">Object serialization context.</param>
    /// <returns>Deserialized class or <c>null</c>.</returns>
    public UClass? FindClassTyped(string className, UDKGeneration generation)
    {
        IntPtr pointer = FindClass(className, bAllowDerived: true);
        return ReadReflectedInstance<UClass>(pointer, generation);
    }

    /// <summary>Searches for an object by name (and optionally class).</summary>
    /// <param name="fullName">Scoped object name (can contain class and outer chain).</param>
    /// <param name="className">(Optional) name of the class that returned object must have.</param>
    /// <param name="bAllowDerived">Whether to allow subclasses.</param>
    /// <returns>Pointer to an object</returns>
    public IntPtr FindObject(string fullName, string? className = null, bool bAllowDerived = true)
    {
        IntPtr classPointer = className is not null ? FindClass(className, bAllowDerived) : IntPtr.Zero;
        return FindObjectInternal(classPointer, fullName, bAllowDerived);
    }

    /// <summary>Searches for an object by name (and optionally class) and deserializes it.</summary>
    /// <typeparam name="T">Defined managed type for deserialization.</typeparam>
    /// <param name="fullName">Scoped object name (can contain class and outer chain).</param>
    /// <param name="generation">Object serialization context.</param>
    /// <returns>Deserialized object or <c>null</c>.</returns>
    public T? FindObjectTyped<T>(string fullName, UDKGeneration generation) where T : UObject
    {
        IntPtr pointer = FindObject(fullName, className: null, bAllowDerived: false);
        return ReadReflectedInstance<T>(pointer, generation);
    }

    IntPtr FindObjectInternal(IntPtr classPointer, string objectFullName, bool bAllowDerived)
    {
        var stringBytes = Encoding.Unicode.GetBytes(objectFullName);

        byte[] inputBuffer = new byte[12 + stringBytes.Length + 2];
        Span<byte> outputBuffer = stackalloc byte[8];

        {
            Array.Fill<byte>(inputBuffer, 0x00);
            Array.Copy(stringBytes, 0, inputBuffer, 12, stringBytes.Length);

            BinaryPrimitives.WriteIntPtrLittleEndian(inputBuffer.AsSpan()[0..8], classPointer);
            BinaryPrimitives.WriteInt32LittleEndian(inputBuffer.AsSpan()[8..12], bAllowDerived ? 0 : 1);
        }

        Execute(inputBuffer, outputBuffer, (asm) =>
        {
            asm.mov(r12, __qword_ptr[rcx]);         // Input buffer.
            asm.mov(r13, __qword_ptr[rcx + 8]);     // Output buffer.

            asm.sub(rsp, 0x20);

            asm.mov(rcx, __qword_ptr[r12]);         // Class to search for.
            asm.mov(rdx, -1);                       // "Any" outer package (magic value).
            asm.lea(r8,  __qword_ptr[r12 + 12]);    // Object path as cw-string, within input buffer.
            asm.mov(r9d, __dword_ptr[r12 + 8]);     // Whether the class match needs to be exact (not 'IsA').

            asm.mov(rax, _addressStaticFindObject);
            asm.call(rax);

            asm.mov(__qword_ptr[r13], rax);
        });

        return BinaryPrimitives.ReadIntPtrLittleEndian(outputBuffer);
    }

    IntPtr FindObjectFastInternal(IntPtr classPointer, FName objectName, bool bAllowDerived, EObjectFlags excludeFlags)
    {
        Span<byte> inputBuffer = stackalloc byte[28];
        Span<byte> outputBuffer = stackalloc byte[8];

        {
            BinaryPrimitives.WriteIntPtrLittleEndian(inputBuffer[0..8], classPointer);
            BinaryPrimitives.WriteInt32LittleEndian(inputBuffer[8..12], objectName.EntryIndex);
            BinaryPrimitives.WriteInt32LittleEndian(inputBuffer[12..16], objectName.NumberPlusOne);
            BinaryPrimitives.WriteInt32LittleEndian(inputBuffer[16..20], bAllowDerived ? 0 : 1);
            BinaryPrimitives.WriteUInt64LittleEndian(inputBuffer[20..28], (ulong)excludeFlags);
        }

        Execute(inputBuffer, outputBuffer, (asm) =>
        {
            asm.mov(r12, __qword_ptr[rcx]);         // Input buffer.
            asm.mov(r13, __qword_ptr[rcx + 8]);     // Output buffer.

            asm.sub(rsp, 0x30);

            asm.mov(rcx, __qword_ptr[r12]);         // Class to search for.
            asm.mov(rdx, 0);                        // Outer package.
            asm.mov(r8,  __qword_ptr[r12 + 8]);     // Object name, this is our primary query.
            asm.mov(r9d, __dword_ptr[r12 + 16]);    // Whether the class match needs to be exact (not 'IsA').
            asm.mov(__dword_ptr[rsp + 0x20], 1);    // Whether "any package" would do (must be TRUE to accommodate the null package pointer).

            asm.mov(rax, __qword_ptr[r12 + 20]);
            asm.mov(__qword_ptr[rsp + 0x24], rax);  // Flags to filter out sought-for objects.

            asm.mov(rax, _addressStaticFindObjectFastInternal);
            asm.call(rax);

            asm.mov(__qword_ptr[r13], rax);
        });

        return BinaryPrimitives.ReadIntPtrLittleEndian(outputBuffer);
    }

    #endregion


    #region Value reading.

    const int FArraySize = 16;
    const int FNameSize = 8;
    const int IntPtr64Size = 8;

    /// <summary>
    /// Reads <c>FArray</c> / <c>TArray</c> components.
    /// </summary>
    public FArray ReadArray(IntPtr address)
    {   
        Span<byte> arrayView = stackalloc byte[FArraySize];
        _process.ReadMemoryChecked(address, arrayView);
        return new FArray(arrayView);
    }

    /// <summary>
    /// Reads bytes of a <c>TArray</c> item.
    /// </summary>
    /// <param name="arrayAddress">Absolute address of the array (not the allocation).</param>
    /// <param name="itemIndex">Ordinal number of the item.</param>
    /// <param name="itemBytes">Buffer which receives bytes of the item.</param>
    /// <exception cref="ArgumentException">If <c>itemIndex</c> is out of array bounds.</exception>
    public void ReadArrayItem(IntPtr arrayAddress, int itemIndex, Span<byte> itemBytes)
    {
        var array = ReadArray(arrayAddress);
        var offset = array.GetItemOffset(itemIndex, itemBytes.Length);
        _process.ReadMemoryChecked(offset, itemBytes);
    }

    /// <summary>
    /// Reads number of <see cref="FNameEntry"/> pointers in the <c>FName::Names</c> array.
    /// </summary>
    public int ReadNameCount() => ReadArray(_addressNames).Count;

    /// <summary>
    /// Reads an <see cref="FNameEntry"/> by index.
    /// </summary>
    /// <param name="index">Index within <c>FName::Names</c> array.</param>
    public FNameEntry ReadNameEntry(int index)
    {
        if (_generation.Names.TryGetValue(index, out FNameEntry cached))
            return cached;

        Span<byte> bytes = stackalloc byte[8];
        ReadArrayItem(_addressNames, index, bytes);
        var pointer = BinaryPrimitives.ReadIntPtrLittleEndian(bytes);

        if (pointer == IntPtr.Zero)
            return new();

        FNameEntry entry = ReadNameEntry(pointer);
        _generation.Names[index] = entry;
        return entry;
    }

    /// <summary>
    /// Reads an <see cref="FNameEntry"/> by pointer.
    /// </summary>
    /// <param name="address">Absolute address of the entry.</param>
    public FNameEntry ReadNameEntry(IntPtr address)
    {
        var metaView = new byte[20];

        _stream.Seek(address, SeekOrigin.Begin);
        _stream.ReadExactly(metaView);

        var entry = new FNameEntry(metaView);

        bool bWideChars = (entry.HashIndex & 1) != 0;
        entry.HashIndex >>= 1;

        if (bWideChars)
        {
            // This is a Unicode (UCS-2) name.
            List<byte> stringBytes = new(capacity: 256);
            Span<byte> charBytes = stackalloc byte[2];

            for (; ; )
            {
                _stream.ReadExactly(charBytes);
                ushort ch = BinaryPrimitives.ReadUInt16LittleEndian(charBytes);
                if (ch == 0) break;
                stringBytes.AddRange(charBytes);
            }

            var stringView = CollectionsMarshal.AsSpan(stringBytes);
            entry.Text = Encoding.Unicode.GetString(stringView);
        }
        else
        {
            // This is an Ansi (Latin-1) name.
            List<byte> stringBytes = new(capacity: 128);

            byte ch = 0;
            while ((ch = (byte)_stream.ReadByte()) != 0)
                stringBytes.Add(ch);

            var stringView = CollectionsMarshal.AsSpan(stringBytes);
            entry.Text = Encoding.Latin1.GetString(stringView);
        }

        return entry;
    }

    /// <summary>
    /// Resolves an <c>FName</c> value as a string according to Unreal rules.
    /// </summary>
    /// <exception cref="InvalidDataException">If <c>name</c> index points to a null <c>FNameEntry</c> pointer.</exception>
    public string ReadName(FName name)
    {
        FNameEntry entry = ReadNameEntry(name.EntryIndex);
        if (entry.Text is null) throw new InvalidDataException("invalid entry index");
        return name.NumberPlusOne == 0 ? entry.Text : $"{entry.Text}_{name.NumberPlusOne - 1}";
    }

    /// <summary>
    /// Reads number of <see cref="UObject"/> pointers in the <c>UObject::GObjObjects</c> array.
    /// </summary>
    public int ReadObjectCount() => ReadArray(_addressObjects).Count;


    /// <summary>
    /// Reads a pointer value found at a given <c>address</c>.
    /// </summary>
    /// <param name="address">Absolute offset to the pointer's bytes.</param>
    /// <param name="bCheckNull">Whether pointer needs to be checked for being null.</param>
    /// <returns>Deserialized pointer value.</returns>
    /// <exception cref="InvalidDataException">When <c>bCheckNull</c> is set and returned value is zero.</exception>
    public IntPtr ReadPointer(IntPtr address, bool bCheckNull = false)
    {
        Span<byte> bytes = stackalloc byte[IntPtr64Size];
        _process.ReadMemoryChecked(address, bytes);

        var pointer = BinaryPrimitives.ReadIntPtrLittleEndian(bytes);
        if (bCheckNull && pointer == IntPtr.Zero)
            throw new InvalidDataException($"null pointer at {address}");

        return pointer;
    }


    /// <summary>Data (always) required for reading a field.</summary>
    internal record struct FieldContext(
        UDKGeneration Generation, 
        bool AsFName = false, 
        uint BitMask = uint.MaxValue, 
        UScriptStruct? Struct = null,
        UFunction? Delegate = null,
        UClass? Interface = null
    );

    /// <summary>Data required for reading an <see cref="UArrayProperty"/> field.</summary>
    internal record ArrayFieldContext(int FieldSize, ArrayFieldContext? Inner);

    /// <summary>Data required for reading a field within a <see cref="ReadReflectedInstance(Type, nint, UDKGeneration)"/> call tree.</summary>
    internal record struct ReflectedFieldContext(object Instance, FieldInfo Field, int? Index, Queue<RefQueueItem> Queue);


    static int GetValueSize(Type valueType, FieldContext fieldContext)
    {
        return valueType switch
        {
            var t when t == typeof(sbyte) || t == typeof(byte) => sizeof(sbyte),
            var t when t == typeof(short) || t == typeof(ushort) => sizeof(short),
            var t when t == typeof(int) || t == typeof(uint) => sizeof(int),
            var t when t == typeof(long) || t == typeof(ulong) => sizeof(long),
            var t when t == typeof(IntPtr) || t == typeof(UIntPtr) => IntPtr64Size,
            var t when t == typeof(string) => fieldContext.AsFName ? FNameSize : FArraySize,
            var t when t.IsArray => FArraySize,
            var t when t.IsClass => IntPtr64Size,
            _ => throw new ArgumentException($"size lookup for {valueType.Name} is not implemented", nameof(valueType)),
        };
    }

    object? ReadFieldValue(ReadOnlySpan<byte> bytes, Type valueType, FieldContext context,
        ArrayFieldContext? arrayContext, ReflectedFieldContext? reflectedContext)
    {
        if (valueType == typeof(sbyte)) return (sbyte)bytes[0];
        if (valueType == typeof(byte)) return bytes[0];
        if (valueType == typeof(short)) return BinaryPrimitives.ReadInt16LittleEndian(bytes[..sizeof(short)]);
        if (valueType == typeof(ushort)) return BinaryPrimitives.ReadUInt16LittleEndian(bytes[..sizeof(ushort)]);
        if (valueType == typeof(int)) return BinaryPrimitives.ReadInt32LittleEndian(bytes[..sizeof(int)]);
        if (valueType == typeof(uint)) return BinaryPrimitives.ReadUInt32LittleEndian(bytes[..sizeof(uint)]);
        if (valueType == typeof(long)) return BinaryPrimitives.ReadInt64LittleEndian(bytes[..sizeof(long)]);
        if (valueType == typeof(ulong)) return BinaryPrimitives.ReadUInt64LittleEndian(bytes[..sizeof(ulong)]);
        if (valueType == typeof(IntPtr)) return BinaryPrimitives.ReadIntPtrLittleEndian(bytes[..IntPtr64Size]);
        if (valueType == typeof(UIntPtr)) return BinaryPrimitives.ReadUIntPtrLittleEndian(bytes[..IntPtr64Size]);
        if (valueType == typeof(float)) return BinaryPrimitives.ReadSingleLittleEndian(bytes[..sizeof(float)]);
        if (valueType == typeof(double)) return BinaryPrimitives.ReadDoubleLittleEndian(bytes[..sizeof(double)]);

        if (valueType == typeof(bool))
        {
            var fieldInteger = BinaryPrimitives.ReadUInt32LittleEndian(bytes[..sizeof(uint)]);
            var fieldValue = fieldInteger & context.BitMask;

            return fieldValue switch
            {
                0 => false,
                uint value when value == context.BitMask => true,
                uint value => throw new InvalidDataException($"weird boolean value: {value}")
            };
        }

        if (valueType == typeof(FScriptDelegate))
        {
            var objectPointer = BinaryPrimitives.ReadIntPtrLittleEndian(bytes[0..8]);
            var funcName = new FName(bytes[8..16]);

            var fieldValue = new FScriptDelegate()
            {
                Object = ReadReflectedInstance<UObject>(objectPointer, context.Generation),
                FunctionName = ReadName(funcName),
                StaticFunction = context.Delegate,
            };

            return fieldValue;
        }

        if (valueType == typeof(FScriptInterface))
        {
            var objectPointer = BinaryPrimitives.ReadIntPtrLittleEndian(bytes[0..8]);
            var interfacePointer = BinaryPrimitives.ReadIntPtrLittleEndian(bytes[8..16]);

            var fieldValue = new FScriptInterface()
            {
                Object = ReadReflectedInstance<UObject>(objectPointer, context.Generation),
                Interface = interfacePointer,
                StaticInterfaceClass = context.Interface,
            };

            return fieldValue;
        }

        if (valueType == typeof(string))
        {
            if (context.AsFName)
            {
                FName name = new(bytes[..FNameSize]);
                return ReadName(name);
            }
            else
            {
                FArray fieldArray = new(bytes[..FArraySize]);

                if (fieldArray.Count == 0)
                    return string.Empty;

                var byteBuffer = new byte[(fieldArray.Count - 1) * sizeof(ushort)];
                _process.ReadMemoryChecked(fieldArray.Allocation, byteBuffer);

                return Encoding.Unicode.GetString(byteBuffer);
            }
        }

        if (valueType.IsSZArray)
        {
            FArray fieldArray = new(bytes[..FArraySize]);

            var elemType = valueType.GetElementType()!;
            var elemSize = arrayContext?.FieldSize ?? GetValueSize(elemType, context);

            var fieldBuffer = new byte[elemSize];
            var fieldValue = Array.CreateInstance(elemType, fieldArray.Count);

            for (var i = 0; i < fieldArray.Count; i++)
            {
                var itemOffset = fieldArray.GetItemOffset(i, elemSize);
                _process.ReadMemoryChecked(itemOffset, fieldBuffer);

                var itemValue = ReadFieldValue(fieldBuffer, elemType, context, arrayContext?.Inner, reflectedContext);
                fieldValue.SetValue(itemValue, i);
            }

            return fieldValue;
        }

        if (valueType == typeof(DynamicScriptStruct) && context.Struct is UScriptStruct fieldStruct)
        {
            var structSlice = bytes[..fieldStruct.PropertiesSize];

            if (fieldStruct.SuperStruct is not null)
            {
                // To the best of my knowledge, this should *never* be the case.
                throw new InvalidDataException($"{fieldStruct} has non-null super struct");
            }

            DynamicScriptStruct structInstance = new() { _struct = fieldStruct };

            foreach (var fieldProperty in fieldStruct.GetProperties(bWithSuper: false))
            {
                var fieldValue = ReadPropertyInternal(structSlice, null, fieldProperty, context.Generation);
                structInstance._fields.Add(fieldProperty.Name, fieldValue);
            }

            return structInstance;
        }

        if (valueType.IsClass)
        {
            var fieldSlice = bytes[..IntPtr64Size];
            var fieldPointer = BinaryPrimitives.ReadIntPtrLittleEndian(fieldSlice);

            if (fieldPointer == IntPtr.Zero)
                return null;

            if (reflectedContext is ReflectedFieldContext rctx)
            {
                // We only have a ReflectedFieldContext when in a ReadReflectedInstance call tree,
                // which means we must push references to a queue defined somewhere up the call stack.
                rctx.Queue.Enqueue(new(rctx.Instance, rctx.Field, valueType, fieldPointer, rctx.Index));
                return null;
            }
            else
            {
                // We do not have a ReflectedFieldContext when serializing an Unreal-reflected property,
                // so we should read a new instance directly. Internally it will create a new reference queue
                // and iterate all the instances it discovers down that reference tree.
                Debug.Assert(reflectedContext is null);
                return ReadReflectedInstance(valueType, fieldPointer, context.Generation);
            }
        }

        if (valueType.IsEnum)
        {
            var enumBaseType = Enum.GetUnderlyingType(valueType);

            if (enumBaseType == typeof(uint))
            {
                var fieldInteger = BinaryPrimitives.ReadUInt32LittleEndian(bytes[..sizeof(uint)]);
                return Enum.ToObject(valueType, fieldInteger);
            }

            if (enumBaseType == typeof(ulong))
            {
                var fieldInteger = BinaryPrimitives.ReadUInt64LittleEndian(bytes[..sizeof(ulong)]);
                return Enum.ToObject(valueType, fieldInteger);
            }
        }

        throw new NotImplementedException($"value reading for {valueType.FullName} is not implemented");
    }

    #endregion


    #region Property reading / writing.

    internal bool CheckPropertyOwnership(UProperty property)
        => (property._sourceRemote?.TryGetTarget(out var checkRemote) ?? false) && checkRemote == this;

    internal static (Type Type, FieldContext Context, ArrayFieldContext? Array) MapPropertyType(UDKGeneration generation, UProperty property)
    {
        (Type type, FieldContext context, ArrayFieldContext? array) = property switch
        {
            UByteProperty => (typeof(byte), new FieldContext(generation), null),
            UIntProperty => (typeof(int), new FieldContext(generation), null),
            UFloatProperty => (typeof(float), new FieldContext(generation), null),
            UBoolProperty prop => (typeof(bool), new FieldContext(generation, BitMask: prop.BitMask), null),
            UStrProperty => (typeof(string), new FieldContext(generation), null),
            UNameProperty => (typeof(string), new FieldContext(generation, AsFName: true), null),
            UDelegateProperty prop => (typeof(FScriptDelegate), new FieldContext(generation, Delegate: prop.Function), null),
            UObjectProperty or UClassProperty or UComponentProperty => (typeof(UObject), new FieldContext(generation), null),
            UInterfaceProperty prop => (typeof(FScriptInterface), new FieldContext(generation, Interface: prop.InterfaceClass), null),
            UStructProperty prop => (typeof(DynamicScriptStruct), new FieldContext(generation, Struct: prop.Struct), null),
            UArrayProperty prop => MapPropertyType(generation, prop.Inner!),
            //UMapProperty => throw new NotImplementedException(),
            _ => throw new NotImplementedException($"{property.Class!.Name} is not supported"),
        };

        if (property is UArrayProperty arrayProperty)
        {
            type = type.MakeArrayType();
            array = new(arrayProperty.Inner!.ElementSize, array);
        }

        return (type, context, array);
    }

    internal byte[] ReadObjectBytes(UObject instance)
    {
        var objectBytes = new byte[instance.Class!.PropertiesSize];
        _process.ReadMemoryChecked(instance._sourcePointer, objectBytes);
        return objectBytes;
    }

    internal object? ReadPropertyInternal(ReadOnlySpan<byte> objectBytes, Type? checkType, UProperty property, UDKGeneration generation)
    {
        Debug.Assert(CheckPropertyOwnership(property), "property does not belong to this remote");
        ReadOnlySpan<byte> slice = objectBytes[property.Offset..];

        var field = MapPropertyType(generation, property);
        var value = ReadFieldValue(slice, field.Type, field.Context, field.Array, null);

        if (checkType is not null && checkType != field.Type)
            throw new ArgumentException($"resolved property type {field.Type}, expected {checkType}");

        return value;
    }

    internal void WritePropertyInternal(Span<byte> objectBytes, object? fieldValue, UProperty property, UDKGeneration generation)
    {
        Debug.Assert(CheckPropertyOwnership(property), "property does not belong to this remote");
        Span<byte> slice = objectBytes[property.Offset..];

        var field = MapPropertyType(generation, property);
        // TODO: Continue property serialization...

        throw new NotImplementedException();
    }

    #endregion


    #region Instance reading.

    object? ReadReflectedInstanceInternal(Type type, IntPtr address, UDKGeneration generation,
        Queue<RefQueueItem> refQueue, out UClassAttribute classAttribute)
    {
        if (address == IntPtr.Zero)
        {
            classAttribute = new(string.Empty, 0);
            return null;
        }

        if (generation.Instances.TryGetValue(address, out var saved))
        {
            // Generally, we would like to avoid recursive re-deserialization of same instances.
            // However when deserializing an instance cached with a higher type, we want to update it.

            (object savedInstance, Type savedType) = saved;
            if (!type.IsSubclassOf(savedInstance.GetType()))
            {
                classAttribute = _classAttributeCache[savedType];
                return savedInstance;
            }
        }

        classAttribute = Attribute.GetCustomAttribute(type, typeof(UClassAttribute)) as UClassAttribute
            ?? throw new InvalidOperationException($"type {type.Name} is not reflected");
        _classAttributeCache[type] = classAttribute;

        var objectInstance = Activator.CreateInstance(type)!;
        generation.Instances[address] = (objectInstance, type);

        if (objectInstance is UObject @object)
        {
            _sourcePointerField.SetValue(@object, address);
            _sourceRemoteField.SetValue(@object, new WeakReference<UDKRemote>(this));
            _sourceGenerationField.SetValue(@object, new WeakReference<UDKGeneration>(generation));
        }

        var objectBytes = _objectMemoryPool.Rent(classAttribute.FixedSize);
        _process.ReadMemoryChecked(address, objectBytes.AsSpan()[..classAttribute.FixedSize]);

        if (!_fieldArrayCache.TryGetValue(type, out (FieldInfo, UFieldAttribute)[]? typeFields))
        {
            IEnumerable<(FieldInfo, UFieldAttribute)> enumerateReflectedFields()
            {
                foreach (FieldInfo fieldInfo in type.GetFields())
                {
                    // Fields on reflected types are allowed to not be reflected.
                    if (fieldInfo.GetCustomAttribute(typeof(UFieldAttribute)) is UFieldAttribute fieldAttribute)
                        yield return (fieldInfo, fieldAttribute);
                }
            }

            typeFields = enumerateReflectedFields().ToArray();
            _fieldArrayCache.Add(type, typeFields);
        }

        foreach (var fieldPair in typeFields!)
        {
            (FieldInfo fieldInfo, UFieldAttribute fieldAttribute) = fieldPair;

            FieldContext context = new(generation, fieldAttribute.AsFName);
            ReflectedFieldContext reflectedContext = new(objectInstance, fieldInfo, null, refQueue);

            var fieldSlice = objectBytes.AsSpan()[fieldAttribute.FixedOffset..];
            var fieldValue = ReadFieldValue(fieldSlice, fieldInfo.FieldType, context, null, reflectedContext);

            fieldInfo.SetValue(objectInstance, fieldValue!);
        }

        _objectMemoryPool.Return(objectBytes, clearArray: true);
        return objectInstance;
    }

    object? ReadReflectedInstance(Type type, IntPtr address, UDKGeneration generation, Queue<RefQueueItem> refQueue)
    {
        var instance = ReadReflectedInstanceInternal(type, address, generation, refQueue, out var classAttribute);
        if (instance is null) return default;

        while (refQueue.TryDequeue(out RefQueueItem item))
        {
            var (outer, field, qtype, pointer, index) = item;
            var valueInstance = ReadReflectedInstanceInternal(qtype, pointer, generation, refQueue, out var valueClassAttribute);

            if (valueInstance is null) continue;

            if (CheckNeedsDowncast(valueInstance, valueClassAttribute.Name, out Type valueLowerType))
            {
                refQueue.Enqueue(new(outer, field, valueLowerType, pointer, index));
                continue;
            }

            if (index is null)
            {
                // Instance needs to go directly to a reflected field.
                field.SetValue(outer, valueInstance);
            }
            else
            {
                // Instance needs to be propagated to an item within a reflected array field.
                var array = (Array)field.GetValue(outer)!;
                array.SetValue(valueInstance, index.Value!);
            }

            if (valueInstance is UObject @object && @object.Class is null)
            {
                // If UObject.Class is null, CheckNeedsDowncast(..) couldn't have checked for a downcast,
                // so we'll keep re-enqueuing this instance until it can actually check the reflected class.
                refQueue.Enqueue(new(outer, field, valueInstance.GetType(), pointer, index));
            }
        }

        if (CheckNeedsDowncast(instance, classAttribute.Name, out var lowerType))
            return ReadReflectedInstance(lowerType, address, generation, refQueue);

        return instance;
    }

    static bool CheckNeedsDowncast(object checkedInstance, string staticClassName, out Type lowerType)
    {
        if (checkedInstance is UObject @object)
        {
            string? realClassName = @object.Class?.Name;
            if (staticClassName != realClassName && !string.IsNullOrEmpty(realClassName))
            {
                Type? lowerTypeChecked = realClassName switch
                {
                    "Field" => typeof(UField),
                    "Struct" => typeof(UStruct),
                    "State" => typeof(UState),
                    "Class" => typeof(UClass),
                    "Function" => typeof(UFunction),
                    "ScriptStruct" => typeof(UScriptStruct),
                    "Const" => typeof(UConst),
                    "Enum" => typeof(UEnum),
                    "Property" => typeof(UProperty),
                    "ByteProperty" => typeof(UByteProperty),
                    "IntProperty" => typeof(UIntProperty),
                    "FloatProperty" => typeof(UFloatProperty),
                    "BoolProperty" => typeof(UBoolProperty),
                    "StrProperty" => typeof(UStrProperty),
                    "NameProperty" => typeof(UNameProperty),
                    "DelegateProperty" => typeof(UDelegateProperty),
                    "ObjectProperty" => typeof(UObjectProperty),
                    "ClassProperty" => typeof(UClassProperty),
                    "ComponentProperty" => typeof(UComponentProperty),
                    "InterfaceProperty" => typeof(UInterfaceProperty),
                    "StructProperty" => typeof(UStructProperty),
                    "ArrayProperty" => typeof(UArrayProperty),
                    "MapProperty" => typeof(UMapProperty),
                    _ => null,
                };

                if (lowerTypeChecked?.IsSubclassOf(checkedInstance.GetType()) ?? false)
                {
                    lowerType = lowerTypeChecked;
                    return true;
                }
            }
        }

        lowerType = typeof(void);
        return false;
    }

    /// <summary>Deserializes an instance of a reflected type passed as a <see cref="Type"/> value.</summary>
    /// <param name="type">Type value annotated with reflection attributes (<see cref="UClassAttribute"/>, <see cref="UFieldAttribute"/>).</param>
    /// <param name="address">Remote object pointer (as an absolute offset).</param>
    /// <param name="generation">Object serialization context.</param>
    /// <returns>Deserialized <see cref="object"/>.</returns>
    public object? ReadReflectedInstance(Type type, IntPtr address, UDKGeneration generation)
        => ReadReflectedInstance(type, address, generation, []);

    /// <summary>Deserializes an instance of a reflected type.</summary>
    /// <typeparam name="T">Destination type, must be annotated with <see cref="UClassAttribute"/>.</typeparam>
    /// <param name="address">Remote object pointer (as an absolute offset).</param>
    /// <param name="generation">Object serialization context.</param>
    /// <returns>Deserialized object cast to <c>T</c>.</returns>
    public T? ReadReflectedInstance<T>(IntPtr address, UDKGeneration generation)
        => (T?)ReadReflectedInstance(typeof(T), address, generation);

    #endregion

}
