namespace Security.ConfigGuard;

/// <summary>
/// The set of configuration keys a service refuses to boot without — and the environments
/// in which that refusal is enforced.
/// </summary>
/// <remarks>
/// <para>
/// <b>Environment semantics (the whole point of this package).</b> The guard throws only in
/// <see cref="EnforcedEnvironments"/>, which defaults to <c>Production</c> and <c>Staging</c>.
/// <c>Development</c> and <c>Testing</c> are exempt by design: dev sentinels live in
/// <c>appsettings.Development.json</c> and test harnesses reuse them, so enforcing there
/// would break every dev run and every test — and a mis-scoped guard crash-loops the very
/// deployment it was meant to protect.
/// </para>
/// <para>
/// A guarded secret's VALUE is never logged, echoed, or put in an exception message. Only the
/// key name and a <see cref="SecretWeakness"/> reason are reported.
/// </para>
/// </remarks>
public sealed class SecretGuardOptions
{
  /// <summary>Default <see cref="SecretRequirement.MinimumLength"/> (characters).</summary>
  public const int DefaultMinimumLength = 32;

  /// <summary>Default <see cref="SecretRequirement.MinimumDistinctCharacters"/>.</summary>
  public const int DefaultMinimumDistinctCharacters = 4;

  /// <summary>The ASP.NET Core environment name for production.</summary>
  public const string ProductionEnvironment = "Production";

  /// <summary>The ASP.NET Core environment name for staging.</summary>
  public const string StagingEnvironment = "Staging";

  private readonly List<SecretRequirement> requirements = new();

  private readonly HashSet<string> enforcedEnvironments =
    new(new[] { ProductionEnvironment, StagingEnvironment }, StringComparer.OrdinalIgnoreCase);

  /// <summary>The guarded keys, in registration order.</summary>
  public IReadOnlyList<SecretRequirement> Requirements => this.requirements;

  /// <summary>
  /// The environments in which a weak secret is fatal. Defaults to
  /// <c>{ Production, Staging }</c>; everything else (notably <c>Development</c> and
  /// <c>Testing</c>) is exempt.
  /// </summary>
  public IReadOnlyCollection<string> EnforcedEnvironments => this.enforcedEnvironments;

  /// <summary>
  /// Requires <paramref name="configKey"/> to be present, non-empty, and strong. Optionally
  /// tunes the rules for that one key (minimum length, known defaults).
  /// </summary>
  public SecretGuardOptions Require(string configKey, Action<SecretRequirement>? configure = null)
  {
    var requirement = this.GetOrAdd(configKey);
    configure?.Invoke(requirement);
    return this;
  }

  /// <summary>
  /// Registers an exact value for <paramref name="configKey"/> that must never reach an
  /// enforced environment (the dev sentinel, a leaked value, a documented default). Implies
  /// <see cref="Require(string, Action{SecretRequirement}?)"/> for the key.
  /// </summary>
  public SecretGuardOptions RejectKnownDefault(string configKey, string knownDefaultValue)
  {
    this.GetOrAdd(configKey).RejectKnownDefault(knownDefaultValue);
    return this;
  }

  /// <summary>
  /// Replaces the enforced-environment set. Use only with a deliberate reason — the default
  /// (<c>Production</c> + <c>Staging</c>) is the safe pairing, and adding <c>Development</c>
  /// or <c>Testing</c> will break dev runs and the test harness.
  /// </summary>
  public SecretGuardOptions EnforceIn(params string[] environmentNames)
  {
    ArgumentNullException.ThrowIfNull(environmentNames);
    this.enforcedEnvironments.Clear();
    foreach (var name in environmentNames)
    {
      if (!string.IsNullOrWhiteSpace(name))
      {
        this.enforcedEnvironments.Add(name);
      }
    }

    return this;
  }

  /// <summary>True when a weak secret should be fatal in the named environment.</summary>
  public bool IsEnforcedIn(string environmentName) =>
    !string.IsNullOrWhiteSpace(environmentName) && this.enforcedEnvironments.Contains(environmentName);

  private SecretRequirement GetOrAdd(string configKey)
  {
    ArgumentException.ThrowIfNullOrWhiteSpace(configKey);

    var existing = this.requirements.Find(r => string.Equals(r.ConfigKey, configKey, StringComparison.Ordinal));
    if (existing is not null)
    {
      return existing;
    }

    var requirement = new SecretRequirement(configKey);
    this.requirements.Add(requirement);
    return requirement;
  }
}
