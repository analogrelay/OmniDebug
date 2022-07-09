using Microsoft.Extensions.DependencyInjection;

using OmniDebug.Interactive.Commands;

using Spectre.Console;

namespace OmniDebug.Interactive;

public class InteractiveDriver
{
    readonly Dictionary<string, Dictionary<string, ICommand>> _commands = new();
    readonly IAnsiConsole _console;

    public InteractiveDriver(IAnsiConsole console, IEnumerable<ICommand> commands)
    {
        _console = console;
        
        var groups = commands.GroupBy(c => c.Group);
        foreach (var group in groups)
        {
            var groupName = group.Key;
            var groupCommands = group.ToDictionary(c => c.Name, c => c);
            _commands.Add(groupName, groupCommands);
        }
    }

    public async Task<int> RunAsync()
    {
        _console.MarkupLine($"[bold]OmniDebug v{DebuggerHost.Version}[/] Interactive .NET Debugger");

        _commands.TryGetValue(string.Empty, out var rootGroup);

        while (true)
        {
            var prompt = new TextPrompt<string>("> ") { AllowEmpty = true };
            var line = prompt.Show(_console);
            var tokens = Tokenizer.Tokenize(line);
            if (tokens.Count == 0)
            {
                tokens = new[] { "help" };
            }
            else if(tokens[0] == "exit")
            {
                return 0;
            }
            
            // Check if the first word matches a group
            if (_commands.TryGetValue(tokens[0], out var group))
            {
                if (tokens.Count == 1)
                {
                    _console.MarkupLine($"TODO: List commands in group {tokens[0]}");
                }
                else if (group.TryGetValue(tokens[1], out var command))
                {
                    await RunCommandAsync(command, tokens.Skip(2).ToList());
                }
                else
                {
                    _console.MarkupLine($"[red]Group '{tokens[0]}' has no command '{tokens[1]}'[/]");
                }
            }
            // It doesn't, check for a command in the root group ("").
            else if (rootGroup is not null && rootGroup.TryGetValue(tokens[0], out var command))
            {
                await RunCommandAsync(command, tokens.Skip(1).ToList());
            }
            else
            {
                _console.MarkupLine($"[red]Unknown command or group: {tokens[0]}[/]");
            }
        }
    }

    async Task RunCommandAsync(ICommand command, IReadOnlyList<string> args)
    {
        try
        {
            await command.ExecuteAsync(args);
        }
        catch (Exception ex) when (ex is ICommandException cex)
        {
            _console.MarkupLine($"[red]{cex.Message}[/]");
        }
        catch (Exception ex)
        {
            _console.MarkupLine($"[red]Unhandled Exception[/]");
            _console.WriteLine(ex.ToString());
        }
    }

    public static void RegisterAllCommands(IServiceCollection services)
    {
        foreach (var typ in typeof(CommandRegistry).Assembly.GetTypes())
        {
            if (typeof(ICommand).IsAssignableFrom(typ) && typ is { IsClass: true, IsAbstract: false })
            {
                services.AddScoped(typeof(ICommand), typ);
            }
        }
    }
}