﻿using System.ComponentModel;
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
        var function = remote.FindObjectTyped<UFunction>("Function'utgame.UTConsole.InputKey'", generation);
        foreach (var property in function!.GetProperties(bWithSuper: false))
            println($"{property} : {property.PropertyFlags}");

        Debug.Assert(function is not null);
        Debugger.Break();
    }
}
catch (Win32Exception exception) when (!IS_DEBUG)
{
    errorln($"win32 exception: {exception.Message}");
    errorln($"last error code: {exception.ErrorCode}");
    errorln($"stack trace: \n{exception.StackTrace}");
}
catch (Exception exception) when (!IS_DEBUG)
{
    errorln($"generic exception: {exception.Message}");
    errorln($"stack trace: \n{exception.StackTrace}");
}
