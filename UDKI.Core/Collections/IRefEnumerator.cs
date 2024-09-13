namespace UDKI.Core.Collections;

public interface IRefEnumerator<T> : IEnumerator<T>
{
    public ref T CurrentRef { get; }
}