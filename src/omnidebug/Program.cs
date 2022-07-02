using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Configuration;

using OmniDebug;
using OmniDebug.Interactive;
using OmniDebug.Interactive.Logging;

using Spectre.Console;

var host = DebuggerHostBuilder.Create(args)
    .ConfigureServices((context, services) =>
    {
        InteractiveDriver.RegisterAllCommands(services);
        services.AddSingleton(AnsiConsole.Console);
        services.AddSingleton<InteractiveDriver>();
    })
    .ConfigureLogging((context, builder) =>
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ILoggerProvider, AnsiConsoleLoggerProvider>());
        LoggerProviderOptions.RegisterProviderOptions<AnsiConsoleLoggerConfiguration, AnsiConsoleLoggerProvider>(builder.Services);
    })
    .Build();
    
return await host.Services.GetRequiredService<InteractiveDriver>().RunAsync();