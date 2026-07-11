namespace Security.ConfigGuard;

/// <summary>
/// Why a configured secret was rejected. Reported by key name + reason only — the
/// secret VALUE is never included in a message, a log line, or an exception.
/// </summary>
public enum SecretWeakness
{
  /// <summary>The secret passed every check.</summary>
  None = 0,

  /// <summary>The configuration key is absent, empty, or whitespace.</summary>
  Missing,

  /// <summary>The value matches a value explicitly registered as a known default / sentinel.</summary>
  KnownDefault,

  /// <summary>The value is shorter than the configured minimum length.</summary>
  TooShort,

  /// <summary>Every character of the value is the same (e.g. all zeroes).</summary>
  AllSameCharacter,

  /// <summary>The value is hex and every decoded byte is the same (e.g. 0x00 repeated).</summary>
  AllSameByte,

  /// <summary>The value has too few distinct characters to plausibly be random.</summary>
  LowEntropy,
}
