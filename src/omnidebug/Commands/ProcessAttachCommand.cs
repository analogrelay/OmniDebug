using System.Diagnostics;

using Spectre.Console;

namespace OmniDebug.Interactive.Commands;

public class ProcessAttachCommand: ICommand
{
    private readonly IAnsiConsole _console;
    private readonly DebuggerEngine _engine;
    public string Group => "process";
    public string Name => "attach";

    public ProcessAttachCommand(IAnsiConsole console, DebuggerEngine engine)
    {
        _console = console;
        _engine = engine;
    }
    
    public ValueTask ExecuteAsync(IReadOnlyList<string> args)
    {
        if(args.Count == 0)
        {
            _console.WriteLine("No process specified");
            return default;
        }
        
        if (!int.TryParse(args[0], out var processId))
        {
            _console.WriteLine($"Invalid Process ID: {args[0]}");
            return default;
        }

        _engine.AttachToProcess(processId);
        return default;
    }
}