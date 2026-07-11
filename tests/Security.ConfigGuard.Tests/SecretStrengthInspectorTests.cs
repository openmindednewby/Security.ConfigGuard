using Security.ConfigGuard;
using Shouldly;

namespace Security.ConfigGuard.Tests;

public class SecretStrengthInspectorTests
{
  private const string DevSentinel = "0000000000000000000000000000000000000000000000000000000000000001";
  private const string StrongPepper = "9f2c41ab7de05c318a6b4de901f7c2b58d3e6a94017cbe25f8d3a71c46b9e0d2";

  [Theory]
  [InlineData(null)]
  [InlineData("")]
  [InlineData("   ")]
  public void Inspect_flags_missing_values(string? value)
  {
    Inspect(value).ShouldBe(SecretWeakness.Missing);
  }

  [Fact]
  public void Inspect_flags_an_explicitly_registered_known_default()
  {
    var requirement = Requirement(r => r.RejectKnownDefault(DevSentinel));

    SecretStrengthInspector.Inspect(DevSentinel, requirement).ShouldBe(SecretWeakness.KnownDefault);
  }

  [Fact]
  public void Inspect_flags_an_all_zero_value()
  {
    Inspect(new string('0', 64)).ShouldBe(SecretWeakness.AllSameCharacter);
  }

  [Fact]
  public void Inspect_flags_an_all_same_repeated_byte_value()
  {
    // "abab..." is not all-the-same CHARACTER, but decodes to the byte 0xAB repeated.
    Inspect(string.Concat(Enumerable.Repeat("ab", 32))).ShouldBe(SecretWeakness.AllSameByte);
  }

  [Fact]
  public void Inspect_flags_a_value_below_the_minimum_length()
  {
    Inspect("deadbeefdeadbeef").ShouldBe(SecretWeakness.TooShort); // 16 chars, min is 32
  }

  [Fact]
  public void Inspect_flags_a_low_entropy_value()
  {
    // 64 chars, not all-same-char, not a repeated byte, but only 3 distinct characters.
    var value = string.Concat(Enumerable.Repeat("01", 31)) + "02";
    value.Length.ShouldBe(64);

    Inspect(value).ShouldBe(SecretWeakness.LowEntropy);
  }

  [Fact]
  public void Inspect_flags_the_poueni_dev_sentinel_even_without_registration()
  {
    // The generic rules alone catch it (two distinct characters), so the guard protects
    // services that forget to register their sentinel explicitly.
    Inspect(DevSentinel).ShouldBe(SecretWeakness.LowEntropy);
  }

  [Fact]
  public void Inspect_accepts_a_strong_random_value()
  {
    Inspect(StrongPepper).ShouldBe(SecretWeakness.None);
  }

  [Fact]
  public void Inspect_accepts_a_strong_non_hex_value()
  {
    Inspect("Zx8+Kq3Lm9Rt2Vw6Yb1Nc4Pf7Hj0Sd5G").ShouldBe(SecretWeakness.None);
  }

  [Fact]
  public void Describe_never_returns_an_empty_reason()
  {
    foreach (var weakness in Enum.GetValues<SecretWeakness>())
    {
      SecretStrengthInspector.Describe(weakness).ShouldNotBeNullOrWhiteSpace();
    }
  }

  private static SecretWeakness Inspect(string? value) => SecretStrengthInspector.Inspect(value, Requirement());

  private static SecretRequirement Requirement(Action<SecretRequirement>? configure = null)
  {
    var options = new SecretGuardOptions();
    options.Require("Auth:ApiKeyPepper", configure);
    return options.Requirements[0];
  }
}
