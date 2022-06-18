using System.Runtime.InteropServices;

using Spectre.Console;

namespace OmniDebug.Interactive.Commands;

public class RuntimesListCommand: ICommand
{
    private readonly IAnsiConsole _console;
    private readonly DebuggerEngine _engine;

    public string Name => "list";

    public string Group => "runtimes";

    public RuntimesListCommand(IAnsiConsole console, DebuggerEngine engine)
    {
        _console = console;
        _engine = engine;
    }
    
    public ValueTask ExecuteAsync(IReadOnlyList<string> args)
    {
        if(args.Count == 0)
        {
            _console.WriteLine("No process specified");
        }
        else if (!int.TryParse(args[0], out var processId))
        {
            _console.WriteLine($"Invalid Process ID: {args[0]}");
        }
        else
        {
            var table = new Table();
            table.AddColumn("Handle");
            table.AddColumn("Path");

            foreach (var rt in _engine.EnumerateRuntimes(processId))
            {
                table.AddRow($"0x{rt.Handle:X8}", rt.Path ?? "<unknown>");
            }

            _console.Write(table);
        }

        return default;
    }
}