using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;

using Spectre.Console;

namespace OmniDebug.Interactive.Commands;

/// <summary>
/// Represents a command that can be executed in the REPL.
/// </summary>
public interface ICommand
{
    /// <summary>
    /// Gets the name for the command group this command is in, if any.
    /// </summary>
    string Group => "";

    /// <summary>
    /// Gets the name of this command.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Executes this command, given the specified arguments.
    /// </summary>
    /// <param name="args">The arguments provided to the command, not including the command and group name.</param>
    /// <returns>The exit code for the command.</returns>
    ValueTask ExecuteAsync(IReadOnlyList<string> args);
}