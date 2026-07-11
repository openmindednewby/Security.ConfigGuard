namespace Security.ConfigGuard;

/// <summary>
/// Thrown at startup when a guarded configuration secret is missing, weak, or a known
/// default in an enforced environment. The service does not boot.
/// </summary>
/// <remarks>
/// The exception carries the config KEY and the <see cref="SecretWeakness"/> reason.
/// It never carries the secret value — this type is designed to be safe to log verbatim.
/// </remarks>
public sealed class WeakSecretException : InvalidOperationException
{
  internal WeakSecretException(string configKey, SecretWeakness weakness, string environmentName)
    : base(BuildMessage(configKey, weakness, environmentName))
  {
    this.ConfigKey = configKey;
    this.Weakness = weakness;
    this.EnvironmentName = environmentName;
  }

  /// <summary>The offending configuration key (e.g. <c>Auth:ApiKeyPepper</c>).</summary>
  public string ConfigKey { get; }

  /// <summary>Why the value was rejected.</summary>
  public SecretWeakness Weakness { get; }

  /// <summary>The environment the service was booting into (e.g. <c>Production</c>).</summary>
  public string EnvironmentName { get; }

  private static string BuildMessage(string configKey, SecretWeakness weakness, string environmentName) =>
    $"Refusing to start in environment '{environmentName}': the configured secret '{configKey}' is not " +
    $"acceptable because {SecretStrengthInspector.Describe(weakness)}. Set a strong random value via " +
    $"configuration (env: '{ToEnvVarName(configKey)}'), e.g. `openssl rand -hex 32`. " +
    "The offending value is deliberately not shown.";

  private static string ToEnvVarName(string configKey) => configKey.Replace(":", "__", StringComparison.Ordinal);
}
