namespace UDKI.Core;


/// <summary>
/// Scopes instance deserialization to a moment in remote engine runtime.
/// Designed to explicitly handle the fact that most objects are likely to change
/// as the runtime continues, something our class deserializer can't deal with on its own.
/// </summary>
public class UDKGeneration : IDisposable
{
    internal readonly ProcessHandle _processHandle;
    internal readonly List<uint> _frozenThreadIds;

    /// <summary>
    /// Maps <see cref="FNameEntry"/> index in <c>FName::Names</c> to a deserialized entry.
    /// </summary>
    public Dictionary<int, FNameEntry> Names { get; } = [];
    /// <summary>
    /// Maps pointer within process memory to a deserialized instance of a reflected type.
    /// </summary>
    public Dictionary<IntPtr, (object, Type)> Instances { get; } = [];


    public UDKGeneration(ProcessHandle processHandle, bool freezeThreads = false)
    {
        _processHandle = processHandle;
        _frozenThreadIds = freezeThreads ? FreezeThreads() : [];
    }


    List<uint> FreezeThreads()
    {
        return _processHandle.SuspendThreads();
    }

    void UnfreezeThreads()
    {
        _processHandle.ResumeThreads(_frozenThreadIds);
        _frozenThreadIds.Clear();
    }


    #region IDisposable implementation.

    private bool _disposedValue = false;

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposedValue)
        {
            if (_frozenThreadIds.Count != 0)
                UnfreezeThreads();

            Names.Clear();
            Names.TrimExcess(0);

            Instances.Clear();
            Instances.TrimExcess(0);

            _disposedValue = true;
        }
    }

    ~UDKGeneration()
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
