using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using OmniDebug.Interop;

using Spectre.Console;

namespace OmniDebug;

public class DebuggerHostBuilder: IHostBuilder
{
    private readonly IHostBuilder _hostBuilder;

    private DebuggerHostBuilder(IHostBuilder hostBuilder)
    {
        _hostBuilder = hostBuilder;
    }

    public static DebuggerHostBuilder Create(string[] args)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureAppConfiguration(configBuilder =>
            {
                configBuilder.AddCommandLine(args);
                configBuilder.AddEnvironmentVariables("OMNIDEBUG_");
            })
            .ConfigureServices(ConfigureDefaultServices);
        return new DebuggerHostBuilder(hostBuilder);
    }

    private static void ConfigureDefaultServices(HostBuilderContext context, IServiceCollection services)
    {
        services.Configure<DebuggerShimOptions>(context.Configuration.GetSection("DebuggerShim"));
        services.AddSingleton<DebuggerShim>();
        services.AddSingleton<DebuggerEngine>();
    }
    
    public DebuggerHost Build() => BuildCore();

    public IHostBuilder ConfigureHostConfiguration(Action<IConfigurationBuilder> configureDelegate) => _hostBuilder.ConfigureHostConfiguration(configureDelegate);
    public IHostBuilder ConfigureAppConfiguration(Action<HostBuilderContext, IConfigurationBuilder> configureDelegate) => _hostBuilder.ConfigureAppConfiguration(configureDelegate);
    public IHostBuilder ConfigureServices(Action<HostBuilderContext, IServiceCollection> configureDelegate) => _hostBuilder.ConfigureServices(configureDelegate);
    public IHostBuilder UseServiceProviderFactory<TContainerBuilder>(IServiceProviderFactory<TContainerBuilder> factory) where TContainerBuilder : notnull => _hostBuilder.UseServiceProviderFactory(factory);
    public IHostBuilder UseServiceProviderFactory<TContainerBuilder>(Func<HostBuilderContext, IServiceProviderFactory<TContainerBuilder>> factory) where TContainerBuilder : notnull => _hostBuilder.UseServiceProviderFactory(factory);
    public IHostBuilder ConfigureContainer<TContainerBuilder>(Action<HostBuilderContext, TContainerBuilder> configureDelegate) => _hostBuilder.ConfigureContainer(configureDelegate);
    IHost IHostBuilder.Build() => BuildCore();
    public IDictionary<object, object> Properties => _hostBuilder.Properties;
    
    DebuggerHost BuildCore() => new DebuggerHost(_hostBuilder.Build());
}