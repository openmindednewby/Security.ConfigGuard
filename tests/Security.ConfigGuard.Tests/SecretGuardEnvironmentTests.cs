using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Security.ConfigGuard;
using Shouldly;

namespace Security.ConfigGuard.Tests;

/// <summary>
/// The single most important behaviour of this package: fatal in Production/Staging,
/// exempt in Development/Testing.
/// </summary>
public class SecretGuardEnvironmentTests
{
  private const string ConfigKey = "Auth:ApiKeyPepper";
  private const string DevSentinel = "0000000000000000000000000000000000000000000000000000000000000001";
  private const string StrongPepper = "9f2c41ab7de05c318a6b4de901f7c2b58d3e6a94017cbe25f8d3a71c46b9e0d2";

  [Theory]
  [InlineData("Production")]
  [InlineData("Staging")]
  public void Validate_throws_on_the_dev_sentinel_in_enforced_environments(string environmentName)
  {
    var exception = Should.Throw<WeakSecretException>(() => Guard(DevSentinel, environmentName).Validate());

    exception.ConfigKey.ShouldBe(ConfigKey);
    exception.EnvironmentName.ShouldBe(environmentName);
    exception.Weakness.ShouldBe(SecretWeakness.KnownDefault);
  }

  [Theory]
  [InlineData("Development")]
  [InlineData("Testing")]
  public void Validate_is_exempt_in_development_and_testing(string environmentName)
  {
    Should.NotThrow(() => Guard(DevSentinel, environmentName).Validate());
  }

  [Theory]
  [InlineData("Production")]
  [InlineData("Staging")]
  public void Validate_throws_when_the_secret_is_missing_in_enforced_environments(string environmentName)
  {
    var exception = Should.Throw<WeakSecretException>(() => Guard(value: null, environmentName).Validate());

    exception.Weakness.ShouldBe(SecretWeakness.Missing);
  }

  [Fact]
  public void Validate_is_exempt_in_development_when_the_secret_is_missing_entirely()
  {
    Should.NotThrow(() => Guard(value: null, "Development").Validate());
  }

  [Theory]
  [InlineData("Production")]
  [InlineData("Staging")]
  [InlineData("Development")]
  [InlineData("Testing")]
  public void Validate_accepts_a_strong_secret_in_every_environment(string environmentName)
  {
    Should.NotThrow(() => Guard(StrongPepper, environmentName).Validate());
  }

  [Fact]
  public void Validate_message_never_contains_the_secret_value()
  {
    var exception = Should.Throw<WeakSecretException>(() => Guard(DevSentinel, "Production").Validate());

    exception.Message.ShouldNotContain(DevSentinel);
    exception.Message.ShouldContain(ConfigKey);
    exception.Message.ShouldContain("Auth__ApiKeyPepper"); // the env-var form, as remediation help
  }

  [Fact]
  public void Validate_reports_the_first_failing_key_when_several_are_guarded()
  {
    var options = new SecretGuardOptions();
    options.Require("Auth:ApiKeyPepper");
    options.Require("Auth:SigningKey");

    var configuration = Configuration(new Dictionary<string, string?>
    {
      ["Auth:ApiKeyPepper"] = StrongPepper,
      ["Auth:SigningKey"] = string.Empty,
    });

    var exception = Should.Throw<WeakSecretException>(
      () => new SecretGuard(configuration, new FakeHostEnvironment("Production"), options).Validate());

    exception.ConfigKey.ShouldBe("Auth:SigningKey");
  }

  [Fact]
  public void EnforceIn_can_widen_the_enforced_environment_set()
  {
    var options = new SecretGuardOptions()
      .EnforceIn("Production", "Staging", "Canary")
      .Require(ConfigKey);

    var guard = new SecretGuard(
      Configuration(new Dictionary<string, string?> { [ConfigKey] = DevSentinel }),
      new FakeHostEnvironment("Canary"),
      options);

    Should.Throw<WeakSecretException>(() => guard.Validate());
  }

  [Fact]
  public void Default_enforced_environments_are_production_and_staging_only()
  {
    var options = new SecretGuardOptions();

    options.IsEnforcedIn("Production").ShouldBeTrue();
    options.IsEnforcedIn("Staging").ShouldBeTrue();
    options.IsEnforcedIn("Development").ShouldBeFalse();
    options.IsEnforcedIn("Testing").ShouldBeFalse();
  }

  private static SecretGuard Guard(string? value, string environmentName)
  {
    var options = new SecretGuardOptions()
      .Require(ConfigKey)
      .RejectKnownDefault(ConfigKey, DevSentinel);

    var configuration = Configuration(new Dictionary<string, string?> { [ConfigKey] = value });

    return new SecretGuard(configuration, new FakeHostEnvironment(environmentName), options);
  }

  private static IConfiguration Configuration(Dictionary<string, string?> values) =>
    new ConfigurationBuilder().AddInMemoryCollection(values).Build();

  private sealed class FakeHostEnvironment : IHostEnvironment
  {
    public FakeHostEnvironment(string environmentName) => this.EnvironmentName = environmentName;

    public string EnvironmentName { get; set; }

    public string ApplicationName { get; set; } = "Security.ConfigGuard.Tests";

    public string ContentRootPath { get; set; } = ".";

    public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
  }
}
