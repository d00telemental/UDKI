﻿using System.ComponentModel;
using System.Diagnostics;

using UDKI.Core;


#region Textual i/o utilities.

var println = (string text) =>
{
    Console.WriteLine($"  {text}");
};

var printlnc = (ConsoleColor color, string text) =>
{
    Console.ForegroundColor = color;
    Console.WriteLine($"  {text}");
    Console.ResetColor();
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


try
{
    using var remote = new UDKRemote();
    using var generation = remote.CreateGeneration();

    var console = remote.FindObjectTyped<UObject>("UTConsole_1", generation)!;

    remote.CallScript(console, "ClearOutput");

    for (int i = 0; i < 10; i++)
    {
        remote.CallScript(console, "OutputTextLine", $"hello there! (#{i})");
        Thread.Sleep(1250);
    }
}
catch (Win32Exception exception) when (!Debugger.IsAttached)
{
    errorln($"win32 exception: {exception.Message}");
    errorln($"last error code: {exception.ErrorCode}");
    errorln($"stack trace: \n{exception.StackTrace}");
}
catch (Exception exception) when (!Debugger.IsAttached)
{
    errorln($"generic exception: {exception.Message}");
    errorln($"stack trace: \n{exception.StackTrace}");
}
