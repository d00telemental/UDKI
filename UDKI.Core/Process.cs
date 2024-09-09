namespace UDKI.Core;


/// <summary>
/// Type-safe process handle for Win32, with some utilities.
/// </summary>
public class ProcessHandle : IDisposable
{
    internal readonly Process       _process;
    internal readonly ProcessModule _module;
    private bool                    _disposed;

    public ProcessHandle(Process process)
    {
        _process = process;
        _module = _process.MainModule!;
    }

    public static ProcessHandle FindUDK()
    {
        try
        {
            var process = Process.GetProcesses().First(p => p.ProcessName == "UDK");
            return new ProcessHandle(process);
        }
        catch (InvalidOperationException exception)
        {
            throw new Exception("failed to find process by name", exception);
        }
    }

    /// <summary>
    /// Retrieves the process id behind this handle.
    /// </summary>
    public uint Id => (uint)_process.Id;

    /// <summary>
    /// Retrieves information about the main module.
    /// </summary>
    public ProcessModule MainModule => _module;

    /// <summary>
    /// Retrieves the raw process handle.
    /// </summary>
    public IntPtr RawHandle
    {
        get
        {
            if (_disposed)
            {
                // We want to catch this condition even in release builds.
                throw new InvalidOperationException("can't use disposed process handle");
            }

            return _process.Handle;
        }
    }


    #region Remote operations.

    /// <summary>
    /// Creates a thread within the process.
    /// </summary>
    /// <returns>Handle to created thread.</returns>
    public IntPtr CreateThread(IntPtr Address, IntPtr Parameter, out uint Id)
    {
        return Windows.CreateRemoteThread(this, Address, Parameter, out Id);
    }

    /// <summary>
    /// Reads memory within the process.
    /// </summary>
    /// <param name="Address">Address of the memory to read.</param>
    /// <param name="Buffer">Output buffer, its size is expected to be read.</param>
    /// <returns>Number of bytes read into <c>Buffer</c>.</returns>
    public int ReadMemory(IntPtr Address, Span<byte> Buffer)
        => (int)Windows.ReadProcessMemory(this, Address, Buffer);

    /// <summary>
    /// Reads memory within the process.
    /// </summary>
    /// <param name="Address">Address of the memory to read.</param>
    /// <param name="Buffer">Output buffer, its size is expected to be read.</param>
    /// <exception cref="Exception">When not entire <c>Buffer</c> is filled.</exception>
    public void ReadMemoryChecked(IntPtr Address, Span<byte> Buffer)
    {
        int Count = ReadMemory(Address, Buffer);
        if (Count != Buffer.Length)
        {
            Debug.Assert(Count < Buffer.Length);  // It would be very weird for RPM to overread...
            throw new Exception($"only {Count} byte(s) read of {Buffer.Length}");
        }
    }

    /// <summary>
    /// Writes bytes from managed buffer into process memory.
    /// </summary>
    /// <param name="Address">Address of the destination to write to.</param>
    /// <param name="Buffer">Input buffer, its size is expected to be written.</param>
    /// <returns>Number of bytes written into process memory.</returns>
    public int WriteMemory(IntPtr Address, ReadOnlySpan<byte> Buffer)
        => (int)Windows.WriteProcessMemory(this, Address, Buffer);

    /// <summary>
    /// Writes bytes from managed buffer into process memory.
    /// </summary>
    /// <param name="Address">Address of the destination to write to.</param>
    /// <param name="Buffer">Input buffer, its size is expected to be written.</param>
    /// <exception cref="Exception">When not entire <c>Buffer</c> is written.</exception>
    public void WriteMemoryChecked(IntPtr Address, ReadOnlySpan<byte> Buffer)
    {
        int Count = WriteMemory(Address, Buffer);
        if (Count != Buffer.Length)
        {
            Debug.Assert(Count < Buffer.Length);
            throw new Exception($"only {Count} byte(s) written of {Buffer.Length}");
        }
    }

    public List<uint> SuspendThreads()
    {
        List<uint> suspendedThreadIds = [];
        _process.Refresh();

        foreach (ProcessThread thread in _process.Threads)
        {
            IntPtr threadHandle = Windows.OpenThread((uint)thread.Id);
            Windows.SuspendThread(threadHandle, out _);
            Windows.CloseHandle(threadHandle);

            suspendedThreadIds.Add((uint)thread.Id);
        }

        return suspendedThreadIds;
    }

    public void ResumeThreads(List<uint> suspendedThreadIds)
    {
        foreach (uint threadId in suspendedThreadIds)
        {
            IntPtr threadHandle = Windows.OpenThread(threadId);
            Windows.ResumeThread(threadHandle, out _);
            Windows.CloseHandle(threadHandle);
        }
    }

    public IntPtr Alloc(ulong Size)
        => Windows.VirtualAlloc(this, Size);

    public void Free(IntPtr Address)
        => Windows.VirtualFree(this, Address);

    public void ProtectExecutable(IntPtr Address, ulong Size)
        => Windows.VirtualProtectExecutable(this, Address, (UIntPtr)Size);

    public void ProtectWritable(IntPtr Address, ulong Size)
        => Windows.VirtualProtectWritable(this, Address, (UIntPtr)Size);

    #endregion

    #region IDisposable implementation.

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing) _process.Dispose();
            _disposed = true;
        }
    }

    ~ProcessHandle()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

#endregion
}


/// <summary>
/// Exposes memory of a process's main module for streaming input / output.
/// Prefer wrapping it in a <see cref="BufferedStream"/> for continual accesses.
/// </summary>
public sealed class ProcessMemoryStream(ProcessHandle process) : Stream
{
    private readonly ProcessHandle _process = process;
    private long _position = 0;


    #region Stream implementation.

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();
    public override long Position { get => _position; set => Seek(value, SeekOrigin.Begin); }

    public override void Flush() { }

    public override int Read(Span<byte> buffer)
    {
        Debug.Assert(_position >= 0);
        _process.ReadMemoryChecked((nint)_position, buffer);
        _position += buffer.Length;
        return buffer.Length;
    }

    public override int Read(byte[] buffer, int offset, int count)
        => Read(buffer.AsSpan().Slice(offset, count));

    public override int ReadByte() => throw new NotSupportedException("use BufferedStream for reading individual bytes");

    public override long Seek(long offset, SeekOrigin origin)
    {
        switch (origin)
        {
            case SeekOrigin.Begin when offset < 0:
            case SeekOrigin.Current when _position + offset < 0:
                throw new ArgumentException("invalid offset", nameof(offset));
            case SeekOrigin.Begin:
                return (_position = offset);
            case SeekOrigin.Current:
                return (_position += offset);
            case SeekOrigin.End:
                throw new InvalidOperationException("can't seek from end");
            default:
                throw new NotImplementedException();
        }
    }

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        Debug.Assert(_position >= 0);
        _process.WriteMemoryChecked((nint)_position, buffer);
        _position += buffer.Length;
    }

    public override void Write(byte[] buffer, int offset, int count)
        => Write(buffer.AsSpan().Slice(offset, count));

    #endregion
}
