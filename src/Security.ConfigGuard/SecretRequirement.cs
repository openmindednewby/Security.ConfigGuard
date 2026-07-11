namespace Security.ConfigGuard;

/// <summary>
/// One guarded configuration key and the strength rules applied to its value.
/// Built through <see cref="SecretGuardOptions.Require(string, System.Action{SecretRequirement}?)"/>.
/// </summary>
public sealed class SecretRequirement
{
  private readonly HashSet<string> knownDefaults = new(StringComparer.Ordinal);

  internal SecretRequirement(string configKey)
  {
    ArgumentException.ThrowIfNullOrWhiteSpace(configKey);
    this.ConfigKey = configKey;
  }

  /// <summary>
  /// The configuration key being guarded, in <c>Section:Key</c> form (e.g.
  /// <c>Auth:ApiKeyPepper</c>). Environment-variable form (<c>Auth__ApiKeyPepper</c>)
  /// binds to the same key.
  /// </summary>
  public string ConfigKey { get; }

  /// <summary>
  /// Minimum number of characters the configured value must have. Defaults to
  /// <see cref="SecretGuardOptions.DefaultMinimumLength"/> (32) — a 16-byte hex pepper
  /// or a 32-char base64 key both clear it.
  /// </summary>
  public int MinimumLength { get; set; } = SecretGuardOptions.DefaultMinimumLength;

  /// <summary>
  /// Minimum number of DISTINCT characters the value must contain. Defaults to
  /// <see cref="SecretGuardOptions.DefaultMinimumDistinctCharacters"/> (4). A random
  /// hex/base64 secret of any useful length has well over a dozen; a hand-typed
  /// sentinel like <c>0000…0001</c> has two.
  /// </summary>
  public int MinimumDistinctCharacters { get; set; } = SecretGuardOptions.DefaultMinimumDistinctCharacters;

  /// <summary>Values explicitly known to be dev sentinels / documented defaults.</summary>
  public IReadOnlyCollection<string> KnownDefaults => this.knownDefaults;

  /// <summary>
  /// Registers an exact value that must never reach a real deployment — the value that
  /// ships in <c>appsettings.Development.json</c>, a value that appeared in a public
  /// repo, or any previously-leaked secret. Comparison is ordinal and exact; this is
  /// config validation, not an auth path, so constant-time comparison is not needed.
  /// </summary>
  public SecretRequirement RejectKnownDefault(string knownDefaultValue)
  {
    ArgumentException.ThrowIfNullOrWhiteSpace(knownDefaultValue);
    this.knownDefaults.Add(knownDefaultValue);
    return this;
  }

  internal bool IsKnownDefault(string value) => this.knownDefaults.Contains(value);
}
