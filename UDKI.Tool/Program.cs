﻿using System.Buffers.Binary;
using System.Diagnostics;
using UDKI.Core;


#region Textual i/o utilities.

var println = (string text) =>
{
    Console.WriteLine($"  {text}");
};

var errorln = (string text) =>
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"! {text}");
    Console.ResetColor();
};

var queryln = (string text) =>
{
    Console.Write($"> {text}: ");
    return Console.ReadLine()!;
};

#endregion

#if DEBUG
bool IS_DEBUG = true;
#else
bool IS_DEBUG = false;
#endif

try
{
    using var process = ProcessHandle.FindUDK();
    println($"found udk.exe process, id = {process.Id}");

    using var remote = new UDKRemote(process);
    println($"established remote connection");

    using (UDKGeneration generation = remote.CreateGeneration(freezeThreads: false))
    {
        Span<byte> bytes = stackalloc byte[8];
        remote.ReadArrayItem(remote.ResolveMainOffset(UDKOffsets.GObjObjects), 0, bytes);

        IntPtr pointer = BinaryPrimitives.ReadIntPtrLittleEndian(bytes);
        var @object = remote.ReadReflectedInstance<UObject>(pointer, generation);
    }
}
catch (WindowsException exception) when (!IS_DEBUG)
{
    errorln($"win32 exception: {exception.Message}");
    errorln($"last error code: {exception.LastErrorCode}");
    errorln($"stack trace: \n{exception.StackTrace}");
}
catch (Exception exception) when (!IS_DEBUG)
{
    errorln($"generic exception: {exception.Message}");
    errorln($"stack trace: \n{exception.StackTrace}");
}
