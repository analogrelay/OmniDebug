using System.Reflection;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace OmniDebug;

public class DebuggerHost: IHost
{
    public static readonly string Version =
        typeof(DebuggerHost).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion
        ?? typeof(DebuggerHost).Assembly.GetName().Version?.ToString()
        ?? "0.0.0";

    readonly IHost _host;
    DebuggerEngine? _engine;

    public IServiceProvider Services => _host.Services;
    public DebuggerEngine Engine => _engine ??= _host.Services.GetRequiredService<DebuggerEngine>();

    public DebuggerHost(IHost host)
    {
        _host = host;
        throw new NotImplementedException();
    }

    public void Dispose() => _host.Dispose();
    public Task StartAsync(CancellationToken cancellationToken = default) => _host.StartAsync(cancellationToken);
    public Task StopAsync(CancellationToken cancellationToken = default) => _host.StopAsync(cancellationToken);
}