using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Security.ConfigGuard;

/// <summary>
/// Applies <see cref="SecretGuardOptions"/> to the running configuration and refuses to let
/// the service boot when a guarded secret is weak in an enforced environment.
/// </summary>
/// <remarks>
/// The environment policy lives here and nowhere else: enforce in
/// <see cref="SecretGuardOptions.EnforcedEnvironments"/> (default <c>Production</c> +
/// <c>Staging</c>), skip everywhere else (notably <c>Development</c> and <c>Testing</c>).
/// </remarks>
public sealed class SecretGuard
{
  private readonly IConfiguration configuration;
  private readonly IHostEnvironment environment;
  private readonly SecretGuardOptions options;
  private readonly ILogger logger;

  /// <summary>Creates a guard over the supplied configuration and environment.</summary>
  public SecretGuard(
    IConfiguration configuration,
    IHostEnvironment environment,
    SecretGuardOptions options,
    ILogger<SecretGuard>? logger = null)
  {
    ArgumentNullException.ThrowIfNull(configuration);
    ArgumentNullException.ThrowIfNull(environment);
    ArgumentNullException.ThrowIfNull(options);

    this.configuration = configuration;
    this.environment = environment;
    this.options = options;
    this.logger = logger ?? NullLogger<SecretGuard>.Instance;
  }

  /// <summary>
  /// Validates every guarded key. Throws <see cref="WeakSecretException"/> on the first
  /// violation when the current environment is enforced; otherwise logs and returns.
  /// </summary>
  public void Validate()
  {
    var environmentName = this.environment.EnvironmentName;
    var enforced = this.options.IsEnforcedIn(environmentName);

    foreach (var requirement in this.options.Requirements)
    {
      var weakness = SecretStrengthInspector.Inspect(this.configuration[requirement.ConfigKey], requirement);
      if (weakness == SecretWeakness.None)
      {
        continue;
      }

      if (!enforced)
      {
        // Dev/Test deliberately ship sentinel values. Say so once, without the value,
        // so the exemption is visible in logs rather than silent.
        this.logger.LogDebug(
          "SecretGuard: '{ConfigKey}' is weak ({Reason}) but environment '{Environment}' is exempt.",
          requirement.ConfigKey,
          SecretStrengthInspector.Describe(weakness),
          environmentName);
        continue;
      }

      throw new WeakSecretException(requirement.ConfigKey, weakness, environmentName);
    }

    if (enforced && this.options.Requirements.Count > 0)
    {
      this.logger.LogInformation(
        "SecretGuard: {Count} guarded secret(s) passed in environment '{Environment}'.",
        this.options.Requirements.Count,
        environmentName);
    }
  }
}
