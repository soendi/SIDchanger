namespace SidChanger.Sid;

/// <summary>Alle Einzelaktionen, die das Programm ausführen kann.</summary>
[Flags]
public enum ChangeFeature
{
    None = 0,

    /// <summary>Computer-SID in SAM/SECURITY ersetzen (Kernfunktion).</summary>
    MachineSid = 1 << 0,

    /// <summary>ProfilList-Einträge (HKLM\...\ProfileList\S-1-5-21-...) auf die neue SID umschlüsseln.</summary>
    ProfileList = 1 << 1,

    /// <summary>NTFS-Berechtigungen der Benutzerprofile auf die neue SID umschreiben.</summary>
    ProfileAcl = 1 << 2,

    /// <summary>Text-SIDs in Aufgaben-XML und TaskCache korrigieren.</summary>
    TaskScheduler = 1 << 3,

    /// <summary>Computernamen ändern.</summary>
    ComputerName = 1 << 4,

    /// <summary>Computerbeschreibung ändern.</summary>
    ComputerDescription = 1 << 5,

    /// <summary>WSUS-ID / Windows-Update-ID (SusClientId, PingID) erneuern.</summary>
    WsusId = 1 << 6,

    /// <summary>MachineGuid (HKLM\SOFTWARE\Microsoft\Cryptography) erneuern.</summary>
    MachineGuid = 1 << 7,

    /// <summary>Machine ID (SQMClient) erneuern.</summary>
    MachineId = 1 << 8,

    /// <summary>Geräte-ID für moderne Apps erneuern.</summary>
    ModernAppsDeviceId = 1 << 9,

    /// <summary>Globale Geräte-ID erneuern (kann die Windows-Aktivierung beeinflussen).</summary>
    GlobalDeviceId = 1 << 10,

    /// <summary>MSDTC-CID erneuern.</summary>
    MsdtcCid = 1 << 11,

    /// <summary>DHCPv6-DUID erneuern.</summary>
    Dhcpv6Duid = 1 << 12,

    /// <summary>Info-Center-/Benachrichtigungseinstellungen zurücksetzen.</summary>
    ActionCenter = 1 << 13,

    /// <summary>DPAPI-Masterkeys und EFS-Schlüsselmaterial an die neue SID anpassen (experimentell).</summary>
    DpapiEfsKeys = 1 << 14,

    /// <summary>Windows Vault (Anmeldeinformationsverwaltung) vorher sichern und danach wiederherstellen.</summary>
    VaultPreserve = 1 << 15,

    /// <summary>OneDrive zurücksetzen.</summary>
    OneDriveReset = 1 << 16,

    /// <summary>Moderne Apps (Appx) zurücksetzen.</summary>
    ModernAppsReset = 1 << 17,

    /// <summary>Windows-Suche-Datenbank zurücksetzen.</summary>
    SearchReset = 1 << 18,

    /// <summary>SQL-Server-master-Datenbank anpassen (nur wenn SQL Server vorhanden).</summary>
    SqlMaster = 1 << 19,

    /// <summary>McAfee-Agent-ID zurücksetzen (nur wenn McAfee vorhanden).</summary>
    McAfeeId = 1 << 20,

    /// <summary>Standard-Apps zurücksetzen.</summary>
    DefaultAppsReset = 1 << 21,

    /// <summary>Benutzer abmelden, damit keine Dateien gesperrt sind.</summary>
    LogoffOtherUsers = 1 << 22,

    /// <summary>UCPD-Treiber (User Choice Protection Driver) anhalten und deaktivieren.</summary>
    UcpdDisable = 1 << 23,
}

/// <summary>Was nach Abschluss der Änderungen passieren soll.</summary>
public enum PostChangeAction
{
    /// <summary>Nichts tun, nur Hinweis anzeigen.</summary>
    None = 0,

    /// <summary>Neu starten.</summary>
    Reboot = 1,

    /// <summary>Herunterfahren.</summary>
    Shutdown = 2,
}

/// <summary>Vollständiger Auftrag für eine SID-Änderung.</summary>
public sealed class ChangeRequest
{
    /// <summary>Neue SID; null, wenn <see cref="GenerateRandomSid"/> verwendet wird.</summary>
    public MachineSid? NewSid { get; set; }

    /// <summary>Zufällige SID erzeugen (Standard).</summary>
    public bool GenerateRandomSid { get; set; } = true;

    public string? NewComputerName { get; set; }

    public string? NewComputerDescription { get; set; }

    public ChangeFeature Features { get; set; } = FeatureCatalog.DefaultFeatures;

    public PostChangeAction PostAction { get; set; } = PostChangeAction.Reboot;

    /// <summary>Profil-ACLs rekursiv (alle Dateien) oder nur das Profilstammverzeichnis ändern.</summary>
    public bool RecursiveProfileAcl { get; set; } = true;

    /// <summary>Betroffene Registrierungswerte vor der Änderung sichern.</summary>
    public bool BackupRegistry { get; set; } = true;

    /// <summary>Andere angemeldete Benutzer zwangsweise abmelden.</summary>
    public bool ForceLogoffOtherUsers { get; set; }

    /// <summary>Sicherheitsprüfungen (Virenscanner, ausstehende Updates, Domäne) nur warnen statt blockieren.</summary>
    public bool IgnorePreflightWarnings { get; set; }

    /// <summary>Paketfamilien-Filter für das Zurücksetzen moderner Apps ('*' = Platzhalter, '-' = ausschließen).</summary>
    public string AppxFilters { get; set; } = "*";

    /// <summary>SQL-Instanz (leer = Standardinstanz).</summary>
    public string SqlInstance { get; set; } = string.Empty;

    public bool Has(ChangeFeature feature) => (Features & feature) == feature;

    /// <summary>Wird die Computer-SID tatsächlich ersetzt?</summary>
    public bool ChangesMachineSid => Has(ChangeFeature.MachineSid);

    /// <summary>Liefert die endgültige neue SID (erzeugt bei Bedarf eine zufällige).</summary>
    public MachineSid ResolveNewSid()
    {
        if (!GenerateRandomSid && NewSid is not null)
        {
            return NewSid;
        }

        return NewSid ??= SidGenerator.CreateRandom();
    }

    /// <summary>Prüft den Auftrag und liefert verständliche Fehlermeldungen.</summary>
    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (Features == ChangeFeature.None)
        {
            errors.Add("Es ist keine Aktion ausgewählt.");
        }

        if (ChangesMachineSid)
        {
            var sid = ResolveNewSid();
            if (sid.Authority1 == 0 && sid.Authority2 == 0 && sid.Authority3 == 0)
            {
                errors.Add("Die neue SID ist ungültig (A, B und C dürfen nicht alle 0 sein).");
            }
        }

        if (Has(ChangeFeature.ComputerName))
        {
            if (string.IsNullOrWhiteSpace(NewComputerName))
            {
                errors.Add("Für die Namensänderung muss ein Computername angegeben werden.");
            }
            else
            {
                errors.AddRange(ComputerNameRules.Validate(NewComputerName));
            }
        }

        if (Has(ChangeFeature.ComputerDescription) && string.IsNullOrWhiteSpace(NewComputerDescription))
        {
            errors.Add("Für die Änderung der Computerbeschreibung muss ein Text angegeben werden.");
        }

        // Abhängige Aktionen: ein SID-Wechsel ohne die zugehörigen Schritte macht das System unbrauchbar.
        errors.AddRange(FeatureDependencies.Missing(Features));

        return errors;
    }
}
