namespace Security.ConfigGuard;

/// <summary>
/// Pure, environment-agnostic weakness detection for a single secret value.
/// Deliberately has no logging and no I/O so it can be unit-tested exhaustively —
/// the environment policy lives in <see cref="SecretGuard"/>.
/// </summary>
public static class SecretStrengthInspector
{
  private const int HexCharsPerByte = 2;

  /// <summary>
  /// Returns the first weakness found in <paramref name="value"/> under
  /// <paramref name="requirement"/>, or <see cref="SecretWeakness.None"/> if it is acceptable.
  /// </summary>
  public static SecretWeakness Inspect(string? value, SecretRequirement requirement)
  {
    ArgumentNullException.ThrowIfNull(requirement);

    if (string.IsNullOrWhiteSpace(value))
    {
      return SecretWeakness.Missing;
    }

    if (requirement.IsKnownDefault(value))
    {
      return SecretWeakness.KnownDefault;
    }

    if (value.Length < requirement.MinimumLength)
    {
      return SecretWeakness.TooShort;
    }

    if (IsAllSameCharacter(value))
    {
      return SecretWeakness.AllSameCharacter;
    }

    if (IsAllSameByte(value))
    {
      return SecretWeakness.AllSameByte;
    }

    if (DistinctCharacterCount(value) < requirement.MinimumDistinctCharacters)
    {
      return SecretWeakness.LowEntropy;
    }

    return SecretWeakness.None;
  }

  /// <summary>A human-readable reason, safe to log — it never contains the secret value.</summary>
  public static string Describe(SecretWeakness weakness) => weakness switch
  {
    SecretWeakness.Missing => "the value is missing or empty",
    SecretWeakness.KnownDefault => "the value is a known default / dev sentinel",
    SecretWeakness.TooShort => "the value is shorter than the required minimum length",
    SecretWeakness.AllSameCharacter => "every character of the value is identical",
    SecretWeakness.AllSameByte => "every byte of the (hex) value is identical",
    SecretWeakness.LowEntropy => "the value has too few distinct characters to be random",
    _ => "the value is acceptable",
  };

  private static bool IsAllSameCharacter(string value)
  {
    foreach (var c in value)
    {
      if (c != value[0])
      {
        return false;
      }
    }

    return true;
  }

  /// <summary>
  /// Catches the repeated-byte case that survives a character-level check: a hex value like
  /// <c>abababab…</c> decodes to a single byte repeated, which is just as fatal for an HMAC
  /// pepper as all-zeroes.
  /// </summary>
  private static bool IsAllSameByte(string value)
  {
    if (!TryDecodeHex(value, out var bytes))
    {
      return false;
    }

    foreach (var b in bytes)
    {
      if (b != bytes[0])
      {
        return false;
      }
    }

    return true;
  }

  private static bool TryDecodeHex(string value, out byte[] bytes)
  {
    bytes = Array.Empty<byte>();
    if (value.Length % HexCharsPerByte != 0)
    {
      return false;
    }

    try
    {
      bytes = Convert.FromHexString(value);
      return bytes.Length > 0;
    }
    catch (FormatException)
    {
      return false;
    }
  }

  private static int DistinctCharacterCount(string value)
  {
    var seen = new HashSet<char>();
    foreach (var c in value)
    {
      seen.Add(c);
    }

    return seen.Count;
  }
}
