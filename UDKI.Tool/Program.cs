using System.ComponentModel;
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

    var console = remote.FindObjectTyped<UObject>("Console'UTConsole_0'", generation)!;

    //var function = console!.FindFunctionChecked("InputKey");
    //foreach (var param in function.GetParams())
    //{
    //    var color = param.PropertyFlags.HasFlag(EPropertyFlags.ReturnParam) ? ConsoleColor.DarkYellow : ConsoleColor.DarkCyan;
    //    printlnc(color, $"{param.Class!.Name} {param.Name}, offset = {param.Offset}, size = {param.ElementSize}");
    //}

    println($"currently typed string = {console.GetPropertyValue<string>("TypedStr")}");
    println($"max scrollback size = {console.GetPropertyValue<int>("MaxScrollbackSize")}");

    Debugger.Break();
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
