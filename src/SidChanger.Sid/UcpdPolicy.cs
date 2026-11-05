namespace SidChanger.Sid;

/// <summary>Zustand des UCPD-Treibers (User Choice Protection Driver).</summary>
public sealed record UcpdSnapshot(bool Present, bool Running, bool Disabled);

/// <summary>Ergebnis eines Versuchs, den UCPD-Treiber anzuhalten und zu deaktivieren.</summary>
public sealed record UcpdOutcome(bool Stopped, bool Disabled, bool RebootRequired, string Message);

/// <summary>
/// Plattformunabhängige Bewertung des UCPD-Treibers. Der eigentliche Zugriff auf den
/// Dienst-Manager erfolgt in <c>SidChanger.Core</c>; hier liegen nur die Regeln und Texte,
/// damit sie ohne Windows geprüft werden können.
/// </summary>
public static class UcpdPolicy
{
    /// <summary>Name des Treibers im Dienst-Manager.</summary>
    public const string ServiceName = "UCPD";

    /// <summary>Bewertung für die Vorabprüfung: bestanden und angezeigter Text.</summary>
    public static (bool Passed, string Message) Evaluate(UcpdSnapshot snapshot)
    {
        if (!snapshot.Present)
        {
            return (true, "Der UCPD-Treiber ist nicht vorhanden (ältere Windows-Version).");
        }

        if (snapshot.Running)
        {
            return (false,
                "Der UCPD-Treiber läuft und schützt Teile der Registrierung. Das Programm kann ihn anhalten und " +
                "deaktivieren – dazu genügt ein Klick auf den Link darunter.");
        }

        return snapshot.Disabled
            ? (true, "Der UCPD-Treiber ist gestoppt und als \"deaktiviert\" eingetragen.")
            : (true, "Der UCPD-Treiber ist gestoppt (Starttyp ist aber weiterhin aktiv).");
    }

    /// <summary>Text und Zustand nach einem Anhalteversuch.</summary>
    public static UcpdOutcome DescribeStop(UcpdSnapshot before, bool stopSucceeded, bool disableSucceeded)
    {
        if (!before.Present)
        {
            return new UcpdOutcome(false, false, false,
                "Der UCPD-Treiber ist auf diesem System nicht vorhanden. Es wurde nichts geändert.");
        }

        if (stopSucceeded && disableSucceeded)
        {
            return new UcpdOutcome(true, true, false,
                "Der UCPD-Treiber ist angehalten und als \"deaktiviert\" eingetragen. Er bleibt auch nach dem " +
                "nächsten Neustart aus.");
        }

        if (disableSucceeded)
        {
            return new UcpdOutcome(false, true, true,
                "Der Treiber läuft noch, ist aber als \"deaktiviert\" eingetragen. Kernel-Treiber lassen sich im " +
                "laufenden Betrieb oft nicht anhalten – nach dem nächsten Neustart bleibt UCPD aus.");
        }

        if (stopSucceeded)
        {
            return new UcpdOutcome(true, false, false,
                "Der UCPD-Treiber ist angehalten, konnte aber nicht dauerhaft deaktiviert werden. Nach einem " +
                "Neustart oder Windows-Update kann er wieder starten.");
        }

        return new UcpdOutcome(false, false, false,
            "Der UCPD-Treiber konnte weder angehalten noch deaktiviert werden. Bitte das Programm als " +
            "Administrator ausführen; ein laufender Kernel-Treiber lässt sich teils nur über einen Neustart " +
            "deaktivieren.");
    }
}
