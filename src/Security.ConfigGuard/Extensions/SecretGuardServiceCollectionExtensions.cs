using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Security.ConfigGuard.Extensions;

/// <summary>
/// Registration helpers for the startup secret guard.
/// </summary>
/// <example>
/// <code>
/// builder.AddSecretGuard(o =&gt;
/// {
///   o.Require("Auth:ApiKeyPepper");
///   o.RejectKnownDefault("Auth:ApiKeyPepper", "0000000000000000000000000000000000000000000000000000000000000001");
/// });
/// </code>
/// </example>
public static class SecretGuardServiceCollectionExtensions
{
  /// <summary>
  /// Registers the guard and validates it <b>immediately</b>, while the host is still being
  /// built — so a weak secret in Production/Staging throws before Kestrel ever binds a port.
  /// This is the preferred entry point for an ASP.NET Core service.
  /// </summary>
  public static IHostApplicationBuilder AddSecretGuard(
    this IHostApplicationBuilder builder,
    Action<SecretGuardOptions> configure)
  {
    ArgumentNullException.ThrowIfNull(builder);
    ArgumentNullException.ThrowIfNull(configure);

    var options = BuildOptions(configure);
    builder.Services.AddSecretGuardCore(options);

    // Fail fast, here and now — do not wait for the hosted service.
    new SecretGuard(builder.Configuration, builder.Environment, options).Validate();

    return builder;
  }

  /// <summary>
  /// Registers the guard to run when the host starts (an <see cref="IHostedService"/> that
  /// throws <see cref="WeakSecretException"/> from <c>StartAsync</c>, aborting startup).
  /// Use this overload when only an <see cref="IServiceCollection"/> is in reach.
  /// </summary>
  public static IServiceCollection AddSecretGuard(
    this IServiceCollection services,
    Action<SecretGuardOptions> configure)
  {
    ArgumentNullException.ThrowIfNull(services);
    ArgumentNullException.ThrowIfNull(configure);

    return services.AddSecretGuardCore(BuildOptions(configure));
  }

  private static SecretGuardOptions BuildOptions(Action<SecretGuardOptions> configure)
  {
    var options = new SecretGuardOptions();
    configure(options);
    return options;
  }

  private static IServiceCollection AddSecretGuardCore(this IServiceCollection services, SecretGuardOptions options)
  {
    services.AddSingleton(options);
    services.TryAddSingleton(sp => new SecretGuard(
      sp.GetRequiredService<IConfiguration>(),
      sp.GetRequiredService<IHostEnvironment>(),
      sp.GetRequiredService<SecretGuardOptions>(),
      sp.GetService<ILogger<SecretGuard>>()));

    services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, SecretGuardHostedService>());

    return services;
  }
}
