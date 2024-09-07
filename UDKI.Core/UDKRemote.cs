using Iced.Intel;
using System.Buffers;
using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using static Iced.Intel.AssemblerRegisters;


namespace UDKI.Core;


/// <summary>
/// Connection to a remote UDK for instrumentation.
/// </summary>
public sealed class UDKRemote : IDisposable
{
    private readonly ProcessHandle _process;
    private readonly BufferedStream _stream;

    /// <summary>
    /// Used for types that are unlikely to change, plus all the names.
    /// </summary>
    private readonly UDKGeneration _generation;

    internal record struct PostfixRecord(object Outer, FieldInfo Field, Type type, nint Address);
    private readonly HashSet<PostfixRecord> _postfixes;

    private readonly ArrayPool<byte> _objectMemoryPool;

    private readonly IntPtr _addressObjects;
    private readonly IntPtr _addressNames;

    /// <summary>
    /// Using a really small buffer to reduce risk of running into a protected region.
    /// </summary>
    private const int StreamBufferSize = 128;

    public UDKRemote(ProcessHandle process)
    {
        _process = process;
        _stream = new(new ProcessMemoryStream(_process), StreamBufferSize);
        _generation = new(_process, freezeThreads: false);
        _postfixes = [];
        _objectMemoryPool = ArrayPool<byte>.Create();

        _addressObjects = ResolveMainOffset(UDKOffsets.GObjObjects);
        _addressNames = ResolveMainOffset(UDKOffsets.Names);
    }


    #region IDisposable implementation.

    private bool _disposedValue;

    private void Dispose(bool disposing)
    {
        if (!_disposedValue)
        {
            if (disposing)
            {
                _generation.Dispose();
                _stream.Dispose();
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


    /// <summary>
    /// Resolves a memory offset relative to the main module base into an absolute pointer.
    /// </summary>
    public IntPtr ResolveMainOffset(IntPtr offset)
    {
        Debug.Assert((ulong)offset <= _process.MainModule.BaseSize);
        return _process.MainModule.BaseAddress + offset;
    }

    /// <summary>
    /// Constructs a new access generation, optionally freezing remote threads for the duration of its lifetime.
    /// </summary>
    public UDKGeneration CreateGeneration(bool freezeThreads = false) => new(_process, freezeThreads);


    #region Code execution internals.

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
        return AlignToMultiple((int)stream.Length, 512);
    }

    static byte[] BuildAssembly(Assembler asm, ulong rip)
    {
        using var stream = new MemoryStream();
        asm.Assemble(new StreamCodeWriter(stream), rip);
        return stream.ToArray();
    }

    #endregion

    /// <summary>
    /// Executes a manually-constructed piece of assembly code in a new remote thread.
    /// </summary>
    /// <param name="writeAssemblyBody">Callback that generates the code to execute, absent prologue and epilogue.</param>
    public void ExecuteCode(Action<Assembler> writeAssemblyBody)
    {
        Assembler localAssembler = new(64);

        WriteAssemblyPrologue(localAssembler);
        writeAssemblyBody(localAssembler);
        WriteAssemblyEpilogue(localAssembler);

        var alignedLength = (ulong)EstimateAssemblySize(localAssembler);
        var allocatedBuffer = _process.Alloc(alignedLength);

        var assemblyBinary = BuildAssembly(localAssembler, (ulong)allocatedBuffer);

        Debug.WriteLine($"allocated {alignedLength} byte(s) at {allocatedBuffer} (0x{allocatedBuffer:X})");

        try
        {
            _process.WriteMemoryChecked(allocatedBuffer, assemblyBinary);
            _process.ProtectExecutable(allocatedBuffer, alignedLength);

            var thread = _process.CreateThread(allocatedBuffer, out var id);
            Debug.WriteLine($"created temporary thread with id = {id}");

            Windows.WaitForSingleObject(thread);
            Windows.CloseHandle(thread);
        }
        finally
        {
            _process.Free(allocatedBuffer);
        }
    }


    #region Memory reading.

    /// <summary>
    /// Reads <c>FArray</c> / <c>TArray</c> components.
    /// </summary>
    public FArray ReadArray(IntPtr address)
    {   
        Span<byte> arrayView = stackalloc byte[16];
        _process.ReadMemoryChecked(address, arrayView);

        return new FArray
        {
            Allocation = BinaryPrimitives.ReadIntPtrLittleEndian(arrayView[0..8]),
            Count = BinaryPrimitives.ReadInt32LittleEndian(arrayView[8..12]),
            Capacity = BinaryPrimitives.ReadInt32LittleEndian(arrayView[12..16])
        };
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
        Span<byte> metaView = stackalloc byte[32];

        _stream.Seek(address, SeekOrigin.Begin);
        _stream.ReadExactly(metaView[..20]);

        FNameEntry entry = new()
        {
            Flags = BinaryPrimitives.ReadUInt64LittleEndian(metaView[0..8]),
            HashIndex = BinaryPrimitives.ReadInt32LittleEndian(metaView[8..12]),
            HashNext = (IntPtr)BinaryPrimitives.ReadUInt64LittleEndian(metaView[12..20]),
        };

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

    #endregion


    #region Object reading internals.

    object? ReadReflectedField(ReadOnlySpan<byte> sourceBytes, object objectInstance,
        FieldInfo fieldInfo, UFieldAttribute fieldAttribute, Dictionary<IntPtr, object> cache, uint depth)
    {
        var valueType = fieldInfo.FieldType;
        var valueOffset = fieldAttribute.FixedOffset;

        if (valueType == typeof(sbyte))
        {
            return (sbyte)sourceBytes[valueOffset];
        }

        if (valueType == typeof(byte))
        {
            return sourceBytes[valueOffset];
        }

        if (valueType == typeof(short))
        {
            var fieldSlice = sourceBytes.Slice(valueOffset, sizeof(short));
            return BinaryPrimitives.ReadInt16LittleEndian(fieldSlice);
        }

        if (valueType == typeof(ushort))
        {
            var fieldSlice = sourceBytes.Slice(valueOffset, sizeof(ushort));
            return BinaryPrimitives.ReadUInt16LittleEndian(fieldSlice);
        }

        if (valueType == typeof(int))
        {
            var fieldSlice = sourceBytes.Slice(valueOffset, sizeof(int));
            return BinaryPrimitives.ReadInt32LittleEndian(fieldSlice);
        }

        if (valueType == typeof(uint))
        {
            var fieldSlice = sourceBytes.Slice(valueOffset, sizeof(uint));
            return BinaryPrimitives.ReadUInt32LittleEndian(fieldSlice);
        }

        if (valueType == typeof(long))
        {
            var fieldSlice = sourceBytes.Slice(valueOffset, sizeof(long));
            return BinaryPrimitives.ReadInt64LittleEndian(fieldSlice);
        }

        if (valueType == typeof(ulong))
        {
            var fieldSlice = sourceBytes.Slice(valueOffset, sizeof(ulong));
            return BinaryPrimitives.ReadUInt64LittleEndian(fieldSlice);
        }

        if (valueType == typeof(IntPtr))
        {
            var fieldSlice = sourceBytes.Slice(valueOffset, 8);
            return BinaryPrimitives.ReadIntPtrLittleEndian(fieldSlice);
        }

        if (valueType == typeof(UIntPtr))
        {
            var fieldSlice = sourceBytes.Slice(valueOffset, 8);
            return BinaryPrimitives.ReadUIntPtrLittleEndian(fieldSlice);
        }

        if (valueType == typeof(string) && fieldAttribute.AsFName)
        {
            var fieldSlice = sourceBytes.Slice(valueOffset, 8);
            FName name = MemoryMarshal.Read<FName>(fieldSlice);
            return ReadName(name);
        }

        if (valueType.IsClass)
        {
            var fieldSlice = sourceBytes.Slice(valueOffset, 8);
            var fieldPointer = BinaryPrimitives.ReadIntPtrLittleEndian(fieldSlice);

            if (fieldPointer == IntPtr.Zero) return null;

            var fieldValue = ReadReflectedInstance(valueType, fieldPointer, cache, depth + 1);
            var classAttribute = Attribute.GetCustomAttribute(fieldValue.GetType(), typeof(UClassAttribute)) as UClassAttribute;

            if (CheckNeedsDowncast(fieldPointer, fieldValue, fieldInfo, objectInstance, classAttribute!, out Type lowerType))
                fieldValue = ReadReflectedInstance(lowerType, fieldPointer, cache, depth + 1);

            return fieldValue;
        }

        throw new NotImplementedException($"deserialization for type {valueType.FullName} is not implemented");
    }

    object ReadReflectedInstance(Type type, IntPtr address, Dictionary<IntPtr, object> cache, uint depth)
    {
        if (cache.TryGetValue(address, out object? saved) && !type.IsSubclassOf(saved!.GetType()))
        {
            // Generally, we would like to avoid recursive re-deserialization of same instances.
            // However when deserializing an instance cached with a higher type, we want to update it.
            return saved;
        }

        var classAttribute = Attribute.GetCustomAttribute(type, typeof(UClassAttribute)) as UClassAttribute
            ?? throw new InvalidOperationException($"type {type.Name} is not reflected");

        var objectBytes = _objectMemoryPool.Rent(classAttribute.FixedSize);
        _process.ReadMemoryChecked(address, objectBytes.AsSpan()[..classAttribute.FixedSize]);

        var objectInstance = Activator.CreateInstance(type)!;
        cache[address] = objectInstance;

        foreach (FieldInfo fieldInfo in type.GetFields())
        {
            // Fields on reflected types are allowed to not be reflected.
            if (fieldInfo.GetCustomAttribute(typeof(UFieldAttribute)) is UFieldAttribute fieldAttribute)
            {
                var fieldValue = ReadReflectedField(objectBytes, objectInstance, fieldInfo, fieldAttribute, cache, depth);
                fieldInfo.SetValueDirect(__makeref(objectInstance), fieldValue!);
            }
        }

        _objectMemoryPool.Return(objectBytes, clearArray: true);

        if (CheckNeedsDowncast(IntPtr.Zero, null, null, objectInstance, classAttribute, out Type lowerType))
        {
            // If we detect a sliced UObject read, re-serialize the instance with a derived type.
            // This is horribly inefficient but we want to pull in all the descendants we can reach.
            objectInstance = ReadReflectedInstance(lowerType, address, cache, depth);
        }

        return objectInstance;
    }

    bool CheckNeedsDowncast(IntPtr fieldPointer, object? fieldInstance, FieldInfo? fieldInfo,
        object outerInstance, UClassAttribute classAttribute, out Type lowerType)
    {
        if (fieldInstance is UObject @object)
        {
            string? className = @object.Class?.Name;

            if (className is null && fieldInfo is not null)
            {
                // If UObject.Class or its name are null, we're 99.9% dealing with a sliced read which will
                // fail to propagate to the outer field instance correctly... So just store enough things to pull
                // the correctly-typed instance from cache at a later point.
                _postfixes.Add(new PostfixRecord(outerInstance, fieldInfo!, fieldInstance!.GetType(), fieldPointer));
            }

            if (classAttribute.Name != className && !string.IsNullOrEmpty(className))
            {
                Type? lowerTypeChecked = className switch
                {
                    "Field" => typeof(UField),
                    "Struct" or "ScriptStruct" => typeof(UStruct),
                    "State" => typeof(UState),
                    "Class" => typeof(UClass),
                    "Function" => typeof(UFunction),
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
                    "InterfaceProperty" => typeof(UInterfaceProperty),
                    "StructProperty" => typeof(UStructProperty),
                    "ArrayProperty" => typeof(UArrayProperty),
                    "MapProperty" => typeof(UMapProperty),
                    _ => null,
                };

                if (lowerTypeChecked?.IsSubclassOf(fieldInstance.GetType()) ?? false)
                {
                    lowerType = lowerTypeChecked;
                    return true;
                }
            }
        }

        lowerType = typeof(void);
        return false;
    }

    #endregion


    /// <summary>
    /// Deserializes an instance of a reflected type.
    /// </summary>
    /// <typeparam name="T">Destination type, must be annotated with <see cref="UClassAttribute"/>.</typeparam>
    /// <param name="address">Remote source pointer (as an absolute offset).</param>
    /// <param name="generation">Generation which should be used for instance tree caching.</param>
    /// <returns>Deserialized object.</returns>
    public T ReadReflectedInstance<T>(IntPtr address, UDKGeneration generation)
    {
        _postfixes.Clear();
        var instance = (T)ReadReflectedInstance(typeof(T), address, generation.Instances, 0);

        // We need to apply postfixes here to handle some recursion edge cases
        // where UObject-derived instance is correctly re-serialized with a lower-derived
        // type and submitted to generation cache, but that re-serialization is not propagated
        // to the receiving instance's field.

        foreach (var (outer, field, type, pointer) in _postfixes)
        {
            var value = ReadReflectedInstance(type, pointer, generation.Instances, 0);
            field.SetValue(outer, value);
        }

        return instance;
    }
}
