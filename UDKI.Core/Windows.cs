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

    internal const uint ERROR_NO_MORE_FILES = 18;

    internal const uint PAGE_READWRITE = 0x0004;
    internal const uint PAGE_EXECUTE_READ = 0x0020;

    internal const uint PROCESS_VM_OPERATION = 0x0008;
    internal const uint PROCESS_VM_READ = 0x0010;
    internal const uint PROCESS_VM_WRITE = 0x0020;

    internal const uint TH32CS_SNAPTHREAD = 0x0004;
    internal const uint TH32CS_SNAPMODULE = 0x0008;

    internal const uint MEM_COMMIT = 0x1000;
    internal const uint MEM_RESERVE = 0x2000;
    internal const uint MEM_DECOMMIT = 0x4000;
    internal const uint MEM_RELEASE = 0x8000;
    internal const uint MEM_TOP_DOWN = 0x00100000;

    internal const uint INFINITE = uint.MaxValue;

    [StructLayout(LayoutKind.Explicit, Size = 1080, CharSet = CharSet.Unicode)]
    internal struct ModuleEntry32W
    {
        [FieldOffset(0)] public uint Size;
        [FieldOffset(4)] public uint ModuleID;
        [FieldOffset(8)] public uint ProcessID;
        [FieldOffset(12)] public uint GlobalUsageCount;
        [FieldOffset(16)] public uint ProcessUsageCount;
        [FieldOffset(24)] public IntPtr BaseAddress;
        [FieldOffset(32)] public uint BaseSize;
        [FieldOffset(40)] public IntPtr Handle;

        [FieldOffset(48)]
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string ModuleName;

        [FieldOffset(560)]
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExePath;
    }

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial int CloseHandle(IntPtr Object);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial IntPtr CreateRemoteThread(IntPtr Process, IntPtr ThreadAttributes, UIntPtr StackSize, IntPtr StartAddress, IntPtr Parameter, uint CreationFlags, IntPtr ThreadId);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial IntPtr CreateToolhelp32Snapshot(uint Flags, uint ProcessId);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial uint GetLastError();

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-module32firstw"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial int Module32FirstW(IntPtr Snapshot, IntPtr ModuleEntryW);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-module32nextw"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial int Module32NextW(IntPtr Snapshot, IntPtr ModuleEntryW);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial IntPtr OpenProcess(uint DesiredAccess, int bInheritHandle, uint ProcessId);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial int ReadProcessMemory(IntPtr Process, IntPtr BaseAddress, IntPtr Buffer, UIntPtr Size, IntPtr NumberOfBytesRead);

    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory"/>
    [LibraryImport("Kernel32.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    internal static partial int WriteProcessMemory(IntPtr Process, IntPtr BaseAddress, IntPtr Buffer, UIntPtr Size, IntPtr NumberOfBytesWritten);

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
    public static void CloseHandle(IntPtr Handle)
    {
        int Result = Invoke.CloseHandle(Handle);
        WindowsException.ThrowIf(Result == Invoke.FALSE, "failed to close handle");
    }

    /// <summary>
    /// Creates a thread in a remote process.
    /// </summary>
    /// <returns>Handle to the created thread.</returns>
    public static IntPtr CreateRemoteThread(ProcessHandle Handle, IntPtr EntryAddress, IntPtr Parameter, out uint ThreadId)
    {
        uint localThreadId = 0u;
        IntPtr localThreadHandle;

        unsafe
        {
            // We omit all the parameters we will not use here...
            localThreadHandle = Invoke.CreateRemoteThread(Handle.RawHandle, IntPtr.Zero, UIntPtr.Zero, EntryAddress, Parameter, 0, (IntPtr)(&localThreadId));
            ThreadId = localThreadId;
        };

        WindowsException.ThrowIf(localThreadHandle == IntPtr.Zero, "failed to create remote thread");
        return localThreadHandle;
    }

    /// <summary>
    /// Retrieves current error code for the last operation.
    /// </summary>
    /// <see href="https://learn.microsoft.com/en-us/windows/win32/Debug/system-error-codes"/>
    public static uint GetLastError() => Invoke.GetLastError();

    /// <summary>
    /// Collects information about all modules in a process.
    /// </summary>
    public static List<ModuleInfo> ListProcessModules(ProcessHandle Handle)
    {
        List<ModuleInfo> Modules = [];

        IntPtr Snapshot = Invoke.CreateToolhelp32Snapshot(Invoke.TH32CS_SNAPMODULE, Handle.Id);
        WindowsException.ThrowIf(Snapshot == Invoke.INVALID_HANDLE_VALUE, "failed to create process snapshot");

        unsafe
        {
            nint StructSize = Marshal.SizeOf<Invoke.ModuleEntry32W>();
            IntPtr ModuleEntryPtr = Marshal.AllocHGlobal(StructSize);

            try
            {
                Invoke.ModuleEntry32W Temporary = new() { Size = (uint)StructSize };
                Marshal.StructureToPtr(Temporary, ModuleEntryPtr, true);

                int LastResult = Invoke.Module32FirstW(Snapshot, ModuleEntryPtr);
                WindowsException.ThrowIf(LastResult != Invoke.TRUE, "failed to retrieve first module info");

                while (LastResult != Invoke.FALSE)
                {
                    Temporary = Marshal.PtrToStructure<Invoke.ModuleEntry32W>(ModuleEntryPtr);

                    Modules.Add(new ModuleInfo()
                    {
                        Name = Temporary.ModuleName.ToString()!,
                        ExePath = Temporary.ExePath.ToString()!,
                        BaseAddress = Temporary.BaseAddress,
                        BaseSize = Temporary.BaseSize,
                    });

                    LastResult = Invoke.Module32NextW(Snapshot, ModuleEntryPtr);
                    uint LastError = Invoke.GetLastError();

                    if (LastResult == Invoke.FALSE && LastError != Invoke.ERROR_NO_MORE_FILES)
                        throw new WindowsException(LastError, "failed to retrieve next module info");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(ModuleEntryPtr);
            }

        };

        WindowsException.ThrowIf(Invoke.CloseHandle(Snapshot) == Invoke.FALSE, "failed to close process snapshot handle");
        return Modules;
    }

    /// <summary>
    /// Opens an existing local process by id.
    /// </summary>
    /// <returns>Valid open handle to the process.</returns>
    public static IntPtr OpenProcess(uint ProcessId, bool AllowOperation, bool AllowRead, bool AllowWrite, bool InheritHandle = false)
    {
        uint AccessFlags = 0u;

        if (AllowOperation) AccessFlags |= Invoke.PROCESS_VM_OPERATION;
        if (AllowRead) AccessFlags |= Invoke.PROCESS_VM_READ;
        if (AllowWrite) AccessFlags |= Invoke.PROCESS_VM_WRITE;

        IntPtr Handle = Invoke.OpenProcess(AccessFlags, InheritHandle ? Invoke.TRUE : Invoke.FALSE, ProcessId);
        WindowsException.ThrowIf(Handle == IntPtr.Zero, "failed to open process");

        return Handle;
    }

    /// <summary>
    /// Reads a block of bytes from process memory into managed buffer.
    /// </summary>
    /// <returns>Number of bytes read.</returns>
    public static ulong ReadProcessMemory(ProcessHandle Handle, IntPtr Address, Span<byte> Buffer)
    {
        nuint BytesRead = 0;

        unsafe
        {
            fixed (byte* OutPtr = Buffer)
            {
                var rc = Invoke.ReadProcessMemory(Handle.RawHandle, Address, (IntPtr)OutPtr, (UIntPtr)Buffer.Length, (IntPtr)(&BytesRead));
                WindowsException.ThrowIf(rc == 0, "failed to read process memory");
            }
        };

        return BytesRead;
    }

    /// <summary>
    /// Writes a block of bytes from managed buffer into process memory.
    /// </summary>
    /// <returns>Number of bytes written.</returns>
    public static ulong WriteProcessMemory(ProcessHandle Handle, IntPtr Address, ReadOnlySpan<byte> Buffer)
    {
        nuint BytesWritten = 0;

        unsafe
        {
            fixed (byte* InPtr = Buffer)
            {
                var rc = Invoke.WriteProcessMemory(Handle.RawHandle, Address, (IntPtr)InPtr, (UIntPtr)Buffer.Length, (IntPtr)(&BytesWritten));
                WindowsException.ThrowIf(rc == 0, "failed to write process memory");
            }
        };

        return BytesWritten;
    }

    /// <summary>
    /// Allocates memory within a virtual address space of a process with read-write permissions.
    /// </summary>
    public static IntPtr VirtualAlloc(ProcessHandle Process, ulong Size)
    {
        IntPtr Address = Invoke.VirtualAllocEx(Process.RawHandle, IntPtr.Zero, (UIntPtr)Size, Invoke.MEM_COMMIT | Invoke.MEM_RESERVE | Invoke.MEM_TOP_DOWN, Invoke.PAGE_READWRITE);
        WindowsException.ThrowIf(Address == IntPtr.Zero, "failed to allocate virtual memory");
        return Address;
    }

    /// <summary>
    /// Deallocates memory within a virtual address space of a process.
    /// </summary>
    public static void VirtualFree(ProcessHandle Process, IntPtr Address)
    {
        int rc = Invoke.VirtualFreeEx(Process.RawHandle, Address, UIntPtr.Zero, Invoke.MEM_RELEASE);
        WindowsException.ThrowIf(rc == 0, "failed to deallocate virtual memory");
    }

    /// <summary>
    /// Updates page protection settings for a block of memory to allow reading and writing.
    /// </summary>
    public static void VirtualProtectWritable(ProcessHandle Process, IntPtr Address, UIntPtr Size)
    {
        uint OldProtect = 0u;
        
        unsafe
        {
            int rc = Invoke.VirtualProtectEx(Process.RawHandle, Address, Size, Invoke.PAGE_READWRITE, (IntPtr)(&OldProtect));
            WindowsException.ThrowIf(rc == 0, "failed to change memory protection to read-write");
        }
    }

    /// <summary>
    /// Updates page protection settings for a block of memory to allow reading and execution.
    /// </summary>
    public static void VirtualProtectExecutable(ProcessHandle Process, IntPtr Address, UIntPtr Size)
    {
        uint OldProtect = 0u;

        unsafe
        {
            int rc = Invoke.VirtualProtectEx(Process.RawHandle, Address, Size, Invoke.PAGE_EXECUTE_READ, (IntPtr)(&OldProtect));
            WindowsException.ThrowIf(rc == 0, "failed to change memory protection to read-execute");
        }
    }

    /// <summary>
    /// Blocks indefinitely until a synchronization object is signaled.
    /// </summary>
    public static void WaitForSingleObject(IntPtr Handle)
    {
        uint rc = Invoke.WaitForSingleObject(Handle, Invoke.INFINITE);
        WindowsException.ThrowIf(rc != 0u, "failed to wait for object, or timeout interval elapsed");
    }

}


/// <summary>
/// Information about a process module.
/// </summary>
public readonly struct ModuleInfo
{
    public readonly string Name { get; init; }
    public readonly string ExePath { get; init; }
    public readonly IntPtr BaseAddress { get; init; }
    public readonly ulong BaseSize { get; init; }
}


/// <summary>
/// Represents a Win32 API error.
/// </summary>
public class WindowsException(uint lastErrorCode, string message) : Exception(message)
{
    // TODO: Consider using system-provided Win32Exception instead of this type.

    public uint LastErrorCode { get; set; } = lastErrorCode;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ThrowIf(bool condition, string message)
    {
        if (condition)
        {
            uint ErrorCode = Windows.GetLastError();
            throw new WindowsException(ErrorCode, message);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ThrowUnless(bool condition, string message)
    {
        if (!condition)
        {
            uint ErrorCode = Windows.GetLastError();
            throw new WindowsException(ErrorCode, message);
        }
    }
}
