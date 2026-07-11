# Security.ConfigGuard

**Refuse to boot on a default/weak secret.** A startup guard that makes "the dev sentinel
reached production" an impossible-to-miss crash instead of a silent, forgeable-hash
vulnerability.

Born from a real finding: a production API-key pepper was still the public dev sentinel
`0000…0001`, so anyone with the key format could recompute every stored hash. Rotating the
value fixes the incident; this package fixes the **bug class**.

## Install

```bash
dotnet add package Security.ConfigGuard
```

## Use

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.AddSecretGuard(o =>
{
    o.Require("Auth:ApiKeyPepper");                      // present + non-empty + strong
    o.RejectKnownDefault(                                 // ...and never THIS value
        "Auth:ApiKeyPepper",
        "0000000000000000000000000000000000000000000000000000000000000001");
});
```

`builder.AddSecretGuard(...)` (the `IHostApplicationBuilder` overload) validates
**immediately**, while the host is still being built — the process throws before Kestrel binds
a port. An `IServiceCollection` overload is also available; it registers an `IHostedService`
that throws from `StartAsync`, aborting host startup.

## Environment semantics (read this)

| Environment | Behaviour |
|---|---|
| `Production` | **Throws `WeakSecretException`** — the service does not boot |
| `Staging` | **Throws `WeakSecretException`** — the service does not boot |
| `Development` | **Exempt** — logs at Debug, boots |
| `Testing` | **Exempt** — logs at Debug, boots |
| anything else | Exempt unless added via `EnforceIn(...)` |

Development and Testing are exempt **by design**: dev sentinels live in
`appsettings.Development.json` and test harnesses reuse them. A guard that fired there would
break every dev run and every test — and a mis-scoped guard crash-loops the very deployment it
was meant to protect. Widen the set deliberately with `o.EnforceIn("Production", "Staging", "Canary")`.

## What counts as weak

Rejected generically, in this order:

| Reason | Example |
|---|---|
| `Missing` | key absent, empty, or whitespace |
| `KnownDefault` | exactly a value passed to `RejectKnownDefault` |
| `TooShort` | shorter than `MinimumLength` (default **32** chars) |
| `AllSameCharacter` | `0000…0000` |
| `AllSameByte` | `abababab…` (hex decoding to one repeated byte) |
| `LowEntropy` | fewer than `MinimumDistinctCharacters` (default **4**) distinct chars — this alone catches `0000…0001` |

Per-key tuning:

```csharp
o.Require("Payments:WebhookSecret", r =>
{
    r.MinimumLength = 40;
    r.RejectKnownDefault("whsec_test_placeholder");
});
```

## Secret hygiene

The secret **value** is never logged, echoed, or placed in an exception message. Only the
config key name and a `SecretWeakness` reason are reported, so `WeakSecretException` is safe
to log verbatim. Comparison is ordinal, not constant-time — this is config validation at boot,
not an authentication path.

## Adopters

- **poueni-api** — guards `Auth:ApiKeyPepper` (the HMAC pepper behind `tenants.api_key_hash`).

## License

MIT
