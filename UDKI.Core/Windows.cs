using System.ComponentModel;
using System.Reflection.Metadata;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace UDKI.Core;


/// <summary>
/// Class which holds all P/Invoke entries for Win32 API.
/// </summary>
internal static partial class Invoke
{
    internal const int TRUE = 1;
    internal const int FALSE = 0;

    internal const IntPtr INVALID_HANDLE_VALUE = -1;

    internal const uint THREAD_SUSPEND_RESUME = 0x0002;

    internal const uint PAGE_READWRITE = 0x0004;
    internal const uint PAGE_EXECUTE_READ = 0x0020;

    internal const uint MEM_COMMIT = 0x1000;
    internal const uint MEM_RESERVE = 0x2000;
    internal const uint MEM_DECOMMIT = 0x4000;
    internal const uint MEM_RELEASE = 0x8000;
    internal const uint MEM_TOP_DOWN = 0x00100000;

    internal const uint INFINITE = uint.MaxValue;

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial int CloseHandle(IntPtr Object);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial IntPtr CreateRemoteThread(IntPtr Process, IntPtr ThreadAttributes, UIntPtr StackSize, IntPtr StartAddress, IntPtr Parameter, uint CreationFlags, IntPtr ThreadId);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial uint GetLastError();

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial int ReadProcessMemory(IntPtr Process, IntPtr BaseAddress, IntPtr Buffer, UIntPtr Size, IntPtr NumberOfBytesRead);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial int WriteProcessMemory(IntPtr Process, IntPtr BaseAddress, IntPtr Buffer, UIntPtr Size, IntPtr NumberOfBytesWritten);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial IntPtr OpenThread(uint DesiredAccess, int bInheritHandle, uint ThreadId);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial uint SuspendThread(IntPtr Handle);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial uint ResumeThread(IntPtr Handle);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial IntPtr VirtualAllocEx(IntPtr Process, IntPtr Address, UIntPtr Size, uint AllocType, uint Protect);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial int VirtualFreeEx(IntPtr Process, IntPtr Address, UIntPtr Size, uint FreeType);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial int VirtualProtectEx(IntPtr Process, IntPtr Address, UIntPtr Size, uint NewProtect, IntPtr OldProtect);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial uint WaitForSingleObject(IntPtr Handle, uint Milliseconds);
}


/// <summary>
/// Public class which provides safe wrappers for some of P/Invoked Win32 API.
/// </summary>
public static class Windows
{
    /// <summary>
    /// Closes an open handle.
    /// </summary>
    public static void CloseHandle(IntPtr handle)
    {
        int result = Invoke.CloseHandle(handle);
        ThrowIf(result == Invoke.FALSE, "failed to close handle");
    }

    /// <summary>
    /// Creates a thread in a remote process.
    /// </summary>
    /// <returns>Handle to the created thread.</returns>
    public static IntPtr CreateRemoteThread(ProcessHandle handle, IntPtr entryAddress, IntPtr entryParam, out uint threadId)
    {
        uint localThreadId = 0u;
        IntPtr localThreadHandle;

        unsafe
        {
            // We omit all the parameters we will not use here...
            localThreadHandle = Invoke.CreateRemoteThread(handle.RawHandle, IntPtr.Zero, UIntPtr.Zero, entryAddress, entryParam, 0, (IntPtr)(&localThreadId));
            threadId = localThreadId;
        };

        ThrowIf(localThreadHandle == IntPtr.Zero, "failed to create remote thread");
        return localThreadHandle;
    }

    /// <summary>
    /// Retrieves current error code for the last operation.
    /// </summary>
    /// <see href="https://learn.microsoft.com/en-us/windows/win32/Debug/system-error-codes"/>
    public static uint GetLastError() => Invoke.GetLastError();

    /// <summary>
    /// Reads a block of bytes from process memory into managed buffer.
    /// </summary>
    /// <returns>Number of bytes read.</returns>
    public static ulong ReadProcessMemory(ProcessHandle handle, IntPtr address, Span<byte> buffer)
    {
        UIntPtr bytesRead = 0;

        unsafe
        {
            fixed (byte* ptr = buffer)
            {
                var rc = Invoke.ReadProcessMemory(handle.RawHandle, address, (IntPtr)ptr, (UIntPtr)buffer.Length, (IntPtr)(&bytesRead));
                ThrowIf(rc == 0, "failed to read process memory");
            }
        };

        return bytesRead;
    }

    /// <summary>
    /// Writes a block of bytes from managed buffer into process memory.
    /// </summary>
    /// <returns>Number of bytes written.</returns>
    public static ulong WriteProcessMemory(ProcessHandle handle, IntPtr address, ReadOnlySpan<byte> buffer)
    {
        UIntPtr bytesWritten = 0;

        unsafe
        {
            fixed (byte* ptr = buffer)
            {
                var rc = Invoke.WriteProcessMemory(handle.RawHandle, address, (IntPtr)ptr, (UIntPtr)buffer.Length, (IntPtr)(&bytesWritten));
                ThrowIf(rc == 0, "failed to write process memory");
            }
        };

        return bytesWritten;
    }

    /// <summary>
    /// Gets an open thread handle with suspend-resume permissions.
    /// </summary>
    public static IntPtr OpenThread(uint id)
    {
        IntPtr handle = Invoke.OpenThread(Invoke.THREAD_SUSPEND_RESUME, Invoke.FALSE, id);
        ThrowIf(handle == IntPtr.Zero, $"failed to open thread {id} for suspend-resume");
        return handle;
    }

    /// <summary>
    /// Increases suspend count on a thread handle.
    /// </summary>
    public static void SuspendThread(IntPtr handle, out uint count)
    {
        uint rc = Invoke.SuspendThread(handle);
        unchecked { ThrowIf(rc == (uint)-1, "failed to suspend thread"); }
        count = rc;
    }

    /// <summary>
    /// Decreases suspend count on a thread handle.
    /// </summary>
    public static void ResumeThread(IntPtr handle, out uint count)
    {
        uint rc = Invoke.ResumeThread(handle);
        unchecked { ThrowIf(rc == (uint)-1, "failed to resume thread"); }
        count = rc;
    }

    /// <summary>
    /// Allocates memory within a virtual address space of a process with read-write permissions.
    /// </summary>
    public static IntPtr VirtualAlloc(ProcessHandle process, ulong size)
    {
        uint allocType = Invoke.MEM_COMMIT | Invoke.MEM_RESERVE | Invoke.MEM_TOP_DOWN;
        IntPtr address = Invoke.VirtualAllocEx(process.RawHandle, IntPtr.Zero, (UIntPtr)size, allocType, Invoke.PAGE_READWRITE);
        ThrowIf(address == IntPtr.Zero, "failed to allocate virtual memory");
        return address;
    }

    /// <summary>
    /// Deallocates memory within a virtual address space of a process.
    /// </summary>
    public static void VirtualFree(ProcessHandle process, IntPtr address)
    {
        int rc = Invoke.VirtualFreeEx(process.RawHandle, address, UIntPtr.Zero, Invoke.MEM_RELEASE);
        ThrowIf(rc == 0, "failed to deallocate virtual memory");
    }

    /// <summary>
    /// Updates page protection settings for a block of memory to allow reading and writing.
    /// </summary>
    public static void VirtualProtectWritable(ProcessHandle process, IntPtr address, UIntPtr size)
    {
        uint prevProtect = 0u;
        
        unsafe
        {
            int rc = Invoke.VirtualProtectEx(process.RawHandle, address, size, Invoke.PAGE_READWRITE, (IntPtr)(&prevProtect));
            ThrowIf(rc == 0, "failed to change memory protection to read-write");
        }
    }

    /// <summary>
    /// Updates page protection settings for a block of memory to allow reading and execution.
    /// </summary>
    public static void VirtualProtectExecutable(ProcessHandle process, IntPtr address, UIntPtr size)
    {
        uint prevProtect = 0u;

        unsafe
        {
            int rc = Invoke.VirtualProtectEx(process.RawHandle, address, size, Invoke.PAGE_EXECUTE_READ, (IntPtr)(&prevProtect));
            ThrowIf(rc == 0, "failed to change memory protection to read-execute");
        }
    }

    /// <summary>
    /// Blocks indefinitely until a synchronization object is signaled.
    /// </summary>
    public static void WaitForSingleObject(IntPtr handle)
    {
        uint rc = Invoke.WaitForSingleObject(handle, Invoke.INFINITE);
        ThrowIf(rc != 0u, "failed to wait for object, or timeout interval elapsed");
    }

    /// <summary>
    /// Throws a <see cref="Win32Exception"/> if <c>condition</c> evaluates true.
    /// </summary>
    public static void ThrowIf(bool condition, string? message)
    {
        if (condition) throw new Win32Exception((int)GetLastError(), message);
    }

}
