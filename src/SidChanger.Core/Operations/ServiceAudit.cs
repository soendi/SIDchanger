using Microsoft.Win32;
using SidChanger.Core.Infrastructure;
using SidChanger.Core.Native;

namespace SidChanger.Core.Operations;

/// <summary>Ein Dienst, der unter einem lokalen Benutzerkonto läuft.</summary>
public sealed record LocalAccountService(string Name, string Account, string? Problem);

/// <summary>
/// Prüft nach der SID-Änderung die Dienste: Dienste unter lokalen Benutzerkonten brauchen
/// danach eventuell ein neues Konto, und die zuvor vom Programm beendeten Dienste werden
/// wieder gestartet.
/// </summary>
public static class ServiceAudit
{
    /// <summary>Dienste, die unter einem lokalen Konto dieser Maschine laufen (nicht LocalSystem &amp; Co.).</summary>
    public static IReadOnlyList<LocalAccountService> FindLocalAccountServices()
    {
        var result = new List<LocalAccountService>();

        try
        {
            using var services = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services");
            if (services is null)
            {
                return result;
            }

            foreach (var name in services.GetSubKeyNames())
            {
                try
                {
                    using var key = services.OpenSubKey(name);
                    if (key?.GetValue("ObjectName") is not string account || !IsLocalAccount(account))
                    {
                        continue;
                    }

                    result.Add(new LocalAccountService(name, account, CheckAccount(account)));
                }
                catch
                {
                    // Einzelne Schlüssel dürfen nicht die ganze Prüfung stoppen.
                }
            }
        }
        catch
        {
            return result;
        }

        return result.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Startet die vom Programm beendeten Dienste wieder.</summary>
    public static (int Started, int Failed) RestartStoppedServices(
        Action<string> log,
        Action<string>? warn,
        CancellationToken ct = default)
    {
        var names = StoppedServicesStore.Load();
        if (names.Count == 0)
        {
            return (0, 0);
        }

        var started = 0;
        var failed = 0;

        foreach (var name in names)
        {
            ct.ThrowIfCancellationRequested();

            if (ServiceControl.GetState(name, out _) == ServiceRunState.NotInstalled)
            {
                log($"{name}: nicht mehr vorhanden, wird übersprungen.");
                continue;
            }

            if (ServiceControl.TryStart(name, TimeSpan.FromSeconds(20), out var detail))
            {
                started++;
                log($"{name}: wieder gestartet.");
            }
            else
            {
                failed++;
                warn?.Invoke($"{name} konnte nicht gestartet werden: {detail}");
            }
        }

        if (failed == 0)
        {
            StoppedServicesStore.Clear();
        }

        return (started, failed);
    }

    private static bool IsLocalAccount(string account) =>
        account.StartsWith(@".\", StringComparison.OrdinalIgnoreCase) ||
        account.StartsWith(Environment.MachineName + @"\", StringComparison.OrdinalIgnoreCase);

    /// <summary>Lässt Windows das Konto auflösen; schlägt das fehl, ist es nach der Änderung weg.</summary>
    private static string? CheckAccount(string account)
    {
        try
        {
            var name = account.StartsWith(@".\", StringComparison.OrdinalIgnoreCase)
                ? account[2..]
                : account[(account.IndexOf('\\') + 1)..];

            _ = new System.Security.Principal.NTAccount(Environment.MachineName, name)
                .Translate(typeof(System.Security.Principal.SecurityIdentifier));

            return null;
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }
}
