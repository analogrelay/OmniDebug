using Microsoft.Extensions.DependencyInjection;

using OmniDebug;
using OmniDebug.Interactive;

using Spectre.Console;

var host = DebuggerHostBuilder.Create(args)
    .ConfigureServices((context, services) =>
    {
        InteractiveDriver.RegisterAllCommands(services);
        services.AddSingleton(AnsiConsole.Console);
        services.AddSingleton<InteractiveDriver>();
    })
    .Build();
    
return await host.Services.GetRequiredService<InteractiveDriver>().RunAsync();