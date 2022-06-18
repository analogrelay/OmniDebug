using System.Runtime.Serialization;

namespace OmniDebug.Interactive;

/// <summary>
/// Marker for interfaces that should be rendered as command line errors.
/// </summary>
public interface ICommandException
{
    /// <summary>
    /// Gets the message to be printed to the console.
    /// </summary>
    public string Message { get; }
}

/// <summary>
/// A standard implementation of <see cref="ICommandException"/>.
/// </summary>
public class CommandException : Exception, ICommandException
{
    public CommandException() { }
    public CommandException(string message) : base(message) { }
    public CommandException(string message, Exception inner) : base(message, inner) { }
}