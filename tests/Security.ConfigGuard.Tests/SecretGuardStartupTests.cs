using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Security.ConfigGuard;
using Security.ConfigGuard.Extensions;
using Shouldly;

namespace Security.ConfigGuard.Tests;

/// <summary>
/// End-to-end proof that a REAL host refuses to boot — not just that a helper method throws.
/// </summary>
public class SecretGuardStartupTests
{
  private const string ConfigKey = "Auth:ApiKeyPepper";
  private const string DevSentinel = "0000000000000000000000000000000000000000000000000000000000000001";
  private const string StrongPepper = "9f2c41ab7de05c318a6b4de901f7c2b58d3e6a94017cbe25f8d3a71c46b9e0d2";

  [Fact]
  public void Host_builder_refuses_to_build_in_production_with_the_dev_sentinel()
  {
    var builder = ApplicationBuilder("Production", DevSentinel);

    var exception = Should.Throw<WeakSecretException>(() => builder.AddSecretGuard(Guarded));

    exception.Weakness.ShouldBe(SecretWeakness.KnownDefault);
    exception.EnvironmentName.ShouldBe("Production");
  }

  [Fact]
  public async Task Host_builder_boots_in_development_with_the_dev_sentinel()
  {
    var builder = ApplicationBuilder("Development", DevSentinel);

    Should.NotThrow(() => builder.AddSecretGuard(Guarded));

    using var host = builder.Build();
    await Should.NotThrowAsync(() => host.StartAsync());
    await host.StopAsync();
  }

  [Fact]
  public async Task Host_builder_boots_in_production_with_a_strong_secret()
  {
    var builder = ApplicationBuilder("Production", StrongPepper);
    builder.AddSecretGuard(Guarded);

    using var host = builder.Build();
    await Should.NotThrowAsync(() => host.StartAsync());
    await host.StopAsync();
  }

  [Fact]
  public async Task Host_start_throws_in_production_when_only_the_service_collection_overload_is_used()
  {
    using var host = new HostBuilder()
      .UseEnvironment("Production")
      .ConfigureAppConfiguration(c => c.AddInMemoryCollection(Values(DevSentinel)))
      .ConfigureServices(services => services.AddSecretGuard(Guarded))
      .Build();

    var exception = await Should.ThrowAsync<WeakSecretException>(() => host.StartAsync());

    exception.ConfigKey.ShouldBe(ConfigKey);
  }

  [Fact]
  public async Task Host_start_succeeds_in_testing_with_the_dev_sentinel()
  {
    using var host = new HostBuilder()
      .UseEnvironment("Testing")
      .ConfigureAppConfiguration(c => c.AddInMemoryCollection(Values(DevSentinel)))
      .ConfigureServices(services => services.AddSecretGuard(Guarded))
      .Build();

    await Should.NotThrowAsync(() => host.StartAsync());
    await host.StopAsync();
  }

  private static void Guarded(SecretGuardOptions options)
  {
    options.Require(ConfigKey);
    options.RejectKnownDefault(ConfigKey, DevSentinel);
  }

  private static HostApplicationBuilder ApplicationBuilder(string environmentName, string? pepper)
  {
    var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
    {
      EnvironmentName = environmentName,
    });

    builder.Configuration.AddInMemoryCollection(Values(pepper));
    return builder;
  }

  private static Dictionary<string, string?> Values(string? pepper) =>
    new() { [ConfigKey] = pepper };
}
