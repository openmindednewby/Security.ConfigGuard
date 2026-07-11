# Build & Publish — Security.ConfigGuard

## Build + test locally

```bash
cd NuGetPackages/Security.ConfigGuard
dotnet restore Security.ConfigGuard.sln
dotnet build Security.ConfigGuard.sln -c Release --no-restore
dotnet test  Security.ConfigGuard.sln -c Release --no-build
```

## Pack

```bash
dotnet pack src/Security.ConfigGuard/Security.ConfigGuard.csproj -c Release -o artifacts
```

## Publish to nuget.org

```powershell
cd NuGetPackages/Security.ConfigGuard
.\publish.ps1 -Bump patch -ApiKey YOUR_NUGET_API_KEY
```

`publish.ps1` bumps the version in `Directory.Build.props`, cleans, restores, builds, packs,
and pushes (`--skip-duplicate`), rolling the version back on failure.

## Notes

- **Until 1.0.0 is on nuget.org**, consumers restore it from a local feed. `poueni-api` does
  this: `services/poueni-api/nuget.config` maps the package id `Security.ConfigGuard` to
  `./local-packages`, which holds the packed `.nupkg`. After publishing to nuget.org, drop the
  `local-packages` folder + the `packageSourceMapping` entry from each consumer.
- **Environment semantics are the contract.** Enforce in `Production` + `Staging`; exempt
  `Development` + `Testing`. Do not change the default enforced set — a guard that fires in dev
  breaks every dev run and every test, and a mis-scoped guard crash-loops production.
- **Never log a secret value.** Messages carry the config key and the reason only. Keep it that
  way; `WeakSecretException` is expected to be safe to log verbatim.
