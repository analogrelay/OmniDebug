using Spectre.Console;

namespace OmniDebug.Interactive.Commands;

public class HelpCommand: ICommand
{
    readonly IAnsiConsole _console;
    
    public string Name => "help";

    public HelpCommand(IAnsiConsole console)
    {
        _console = console;
    }
    
    public ValueTask ExecuteAsync(IReadOnlyList<string> args)
    {
        _console.MarkupLine("TODO: Help");
        return default;
    }
}