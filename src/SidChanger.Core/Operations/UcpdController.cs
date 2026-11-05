using SidChanger.Core.Native;
using SidChanger.Sid;

namespace SidChanger.Core.Operations;

/// <summary>
/// Hält den UCPD-Treiber (User Choice Protection Driver) an und setzt ihn auf „deaktiviert".
/// UCPD schützt Teile der Registrierung und kann Änderungen blockieren, deshalb erledigt
/// das Programm das selbst – ein Verweis in die Dienste-Verwaltung ist nicht nötig.
/// </summary>
public static class UcpdController
{
    /// <summary>Liest den aktuellen Zustand des Treibers.</summary>
    public static UcpdSnapshot Read()
    {
        var state = ServiceControl.GetState(UcpdPolicy.ServiceName, out _);

        if (state == ServiceRunState.NotInstalled)
        {
            return new UcpdSnapshot(false, false, false);
        }

        var startType = ServiceControl.ReadStartType(UcpdPolicy.ServiceName);

        return new UcpdSnapshot(
            Present: state != ServiceRunState.Unknown,
            Running: state == ServiceRunState.Running,
            Disabled: startType == ServiceControl.StartTypeDisabled);
    }

    /// <summary>Hält den Treiber an und trägt ihn als deaktiviert ein.</summary>
    public static UcpdOutcome StopAndDisable(Action<string> log, Action<string>? warn)
    {
        var before = Read();

        if (!before.Present)
        {
            log("UCPD-Treiber ist nicht vorhanden – nichts zu tun.");
            return UcpdPolicy.DescribeStop(before, false, false);
        }

        // Zuerst deaktivieren: das bleibt auch dann wirksam, wenn der Treiber sich im
        // laufenden Betrieb nicht anhalten lässt (häufig bei Kernel-Treibern).
        var disabled = ServiceControl.TrySetStartType(
            UcpdPolicy.ServiceName, ServiceControl.StartTypeDisabled, out var disableDetail);

        if (disabled)
        {
            log("UCPD: Starttyp auf \"deaktiviert\" gesetzt – der Treiber bleibt nach dem Neustart aus.");
        }
        else
        {
            warn?.Invoke("UCPD konnte nicht deaktiviert werden: " + disableDetail);
        }

        var stopped = false;

        if (before.Running)
        {
            stopped = ServiceControl.TryStop(UcpdPolicy.ServiceName, TimeSpan.FromSeconds(20), out var stopDetail);

            if (stopped)
            {
                log("UCPD-Treiber angehalten: " + stopDetail);
            }
            else
            {
                warn?.Invoke("UCPD-Treiber lässt sich nicht anhalten: " + stopDetail);
            }
        }
        else
        {
            log("UCPD-Treiber läuft nicht.");
        }

        var outcome = UcpdPolicy.DescribeStop(before, stopped, disabled);
        log("UCPD: " + outcome.Message);
        return outcome;
    }
}
