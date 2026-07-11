using Microsoft.Extensions.Hosting;

namespace Security.ConfigGuard;

/// <summary>
/// Runs <see cref="SecretGuard.Validate"/> as the host starts. Throwing from
/// <see cref="StartAsync"/> aborts host startup, so a weak secret means the process
/// never serves traffic — a crash at boot, loudly, instead of silently-forgeable hashes.
/// </summary>
internal sealed class SecretGuardHostedService : IHostedService
{
  private readonly SecretGuard guard;

  public SecretGuardHostedService(SecretGuard guard)
  {
    ArgumentNullException.ThrowIfNull(guard);
    this.guard = guard;
  }

  public Task StartAsync(CancellationToken cancellationToken)
  {
    this.guard.Validate();
    return Task.CompletedTask;
  }

  public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
