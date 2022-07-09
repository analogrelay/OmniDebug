using Microsoft.Extensions.Logging;

using Spectre.Console;

namespace OmniDebug.Interactive.Logging;

public class AnsiConsoleLoggerProvider: ILoggerProvider
{
    public void Dispose()
    {
    }

    public ILogger CreateLogger(string categoryName) => new AnsiConsoleLogger(categoryName);
}

public class AnsiConsoleLogger : ILogger
{
    readonly string _categoryName;

    public AnsiConsoleLogger(string categoryName)
    {
        _categoryName = categoryName;
    }

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        var message = formatter(state, exception);
        var markup = logLevel switch
        {
            LogLevel.Critical => $"[red][bold]{message}[/][/]",
            LogLevel.Error => $"[red]{message}[/]",
            LogLevel.Warning => $"[yellow]{message}[/]",
            LogLevel.Debug => $"[grey]{message}[/]",
            LogLevel.Trace => $"[grey]{message}[/]",
            _ => $"{message}",
        };
        AnsiConsole.MarkupLine(markup);
    }

    public bool IsEnabled(LogLevel logLevel) => true;

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
}