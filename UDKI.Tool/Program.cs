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
    while (queryln("Class Name") is string className)
    {
        var uClass = remote.FindClassTyped(className, generation);

        if (uClass?.FuncMap != null)
        {
            println($"{uClass.Name} Function Map:");
            foreach ((string? key, UFunction? uFunction) in uClass.FuncMap)
            {
                println($"\t{key} : {uFunction?.Name}");
            }
            println("");
        }
        else
        {
            println($"Getting {className} Class Failed!");
            break;
        }
    }

    var controller = remote.FindObjectTyped<UObject>("SimplePC_0", generation)!;
    dynamic location = controller.GetPropertyValue<DynamicScriptStruct>("Location");

    println($"player location = ({location.X}, {location.Y}, {location.Z})");

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
