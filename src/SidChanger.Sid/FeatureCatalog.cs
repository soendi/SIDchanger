namespace SidChanger.Sid;

/// <summary>Risikoklasse einer Aktion (für die Darstellung in der GUI).</summary>
public enum RiskLevel
{
    Niedrig = 0,
    Mittel = 1,
    Hoch = 2,
}

/// <summary>Beschreibung einer Einzelaktion für die Oberfläche und die Dokumentation.</summary>
public sealed record FeatureInfo(
    ChangeFeature Feature,
    string Title,
    string Description,
    RiskLevel Risk,
    bool DefaultOn,
    bool RequiresAdmin,
    bool RequiresReboot,
    string RegistrySummary);

/// <summary>Katalog aller Aktionen inklusive der Standardauswahl.</summary>
public static class FeatureCatalog
{
    /// <summary>Alle Aktionen, die standardmäßig aktiviert sind.</summary>
    public const ChangeFeature DefaultFeatures =
        ChangeFeature.MachineSid |
        ChangeFeature.ProfileList |
        ChangeFeature.ProfileAcl |
        ChangeFeature.TaskScheduler |
        ChangeFeature.WsusId |
        ChangeFeature.MachineGuid |
        ChangeFeature.MachineId |
        ChangeFeature.ModernAppsDeviceId |
        ChangeFeature.MsdtcCid |
        ChangeFeature.Dhcpv6Duid |
        ChangeFeature.ActionCenter |
        ChangeFeature.VaultPreserve |
        ChangeFeature.UcpdDisable |
        ChangeFeature.SearchReset;

    public static IReadOnlyList<FeatureInfo> All { get; } = new List<FeatureInfo>
    {
        new(ChangeFeature.MachineSid,
            "Computer-SID ersetzen",
            "Ersetzt die lokale Computer-SID (S-1-5-21-A-B-C) in den Registrierungsdateien SAM und SECURITY durch eine neue Zufalls-SID.",
            RiskLevel.Hoch, true, true, false,
            "HKLM\\SAM\\SAM, HKLM\\SECURITY"),

        new(ChangeFeature.ProfileList,
            "Benutzerprofile umschlüsseln (ProfileList)",
            "Benennt die profilbezogenen Registrierungsschlüssel von der alten auf die neue SID um, damit Windows die vorhandenen Profile weiterverwendet.",
            RiskLevel.Hoch, true, true, false,
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"),

        new(ChangeFeature.ProfileAcl,
            "NTFS-Rechte der Profile anpassen",
            "Schreibt Besitzer und Zugriffsrechte der Profilordner von der alten auf die neue SID um. Ohne diesen Schritt kann der Benutzer nach der Änderung nicht mehr auf sein Profil zugreifen.",
            RiskLevel.Hoch, true, true, false,
            "C:\\Users\\<Profil> (NTFS-ACLs)"),

        new(ChangeFeature.TaskScheduler,
            "Taskplaner-Aufgaben korrigieren",
            "Ersetzt die alte SID in Aufgaben-XML-Dateien und im TaskCache, damit geplante Aufgaben weiterhin ausgeführt werden.",
            RiskLevel.Mittel, true, true, false,
            "C:\\Windows\\System32\\Tasks, HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache"),

        new(ChangeFeature.ComputerName,
            "Computernamen ändern",
            "Vergibt einen neuen NetBIOS-Namen (max. 15 Zeichen). Platzhalter: ? = Zufallszeichen, * = MAC-Adresse.",
            RiskLevel.Niedrig, false, true, true,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName, HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"),

        new(ChangeFeature.ComputerDescription,
            "Computerbeschreibung ändern",
            "Setzt die Beschreibung, die im Netzwerk angezeigt wird.",
            RiskLevel.Niedrig, false, true, false,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\srvcomment"),

        new(ChangeFeature.WsusId,
            "WSUS-ID / Update-ID erneuern",
            "Erzeugt eine neue SusClientId und löscht die alte Prüfsumme sowie die PingID, damit der Rechner im WSUS als neues Gerät erscheint.",
            RiskLevel.Niedrig, true, true, false,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate"),

        new(ChangeFeature.MachineGuid,
            "MachineGuid erneuern",
            "Neue GUID unter Cryptography. Wird von vielen Anwendungen und Installern als Gerätekennung verwendet.",
            RiskLevel.Niedrig, true, true, false,
            "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid"),

        new(ChangeFeature.MachineId,
            "Machine ID (SQM) erneuern",
            "Neue Machine ID für den Kundenzufriedenheits-/Telemetriedienst.",
            RiskLevel.Niedrig, true, true, false,
            "HKLM\\SOFTWARE\\Microsoft\\SQMClient\\MachineId"),

        new(ChangeFeature.ModernAppsDeviceId,
            "Geräte-ID moderner Apps erneuern",
            "Neue Geräte-ID für Store-Apps und App-Dienste.",
            RiskLevel.Mittel, true, true, false,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Store, HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Appx"),

        new(ChangeFeature.GlobalDeviceId,
            "Globale Geräte-ID erneuern",
            "Wie Geräte-ID, wirkt sich aber systemweit aus. Kann die Windows-Aktivierung beeinflussen.",
            RiskLevel.Hoch, false, true, true,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Store\\GlobalDeviceId"),

        new(ChangeFeature.MsdtcCid,
            "MSDTC-CID erneuern",
            "Neue Cluster-/Transaktions-ID des Distributed Transaction Coordinator.",
            RiskLevel.Niedrig, true, true, false,
            "HKLM\\SOFTWARE\\Microsoft\\MSDTC\\CID"),

        new(ChangeFeature.Dhcpv6Duid,
            "DHCPv6-DUID erneuern",
            "Löscht die DHCPv6-Gerätekennung; Windows erzeugt beim nächsten Start automatisch eine neue.",
            RiskLevel.Niedrig, true, true, true,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Dhcpv6DUID"),

        new(ChangeFeature.ActionCenter,
            "Info-Center-Einstellungen zurücksetzen",
            "Setzt die Benachrichtigungs- und Info-Center-Einstellungen zurück (Einstellungen der Benachrichtigungsdienste).",
            RiskLevel.Niedrig, true, true, false,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings"),

        new(ChangeFeature.LogoffOtherUsers,
            "Andere Benutzer abmelden",
            "Meldet alle anderen angemeldeten Sitzungen ab, damit keine Profildateien gesperrt sind. Wird als erster Schritt ausgeführt.",
            RiskLevel.Mittel, false, true, false,
            "Terminaldienste (WTS)"),

        new(ChangeFeature.UcpdDisable,
            "UCPD-Treiber anhalten und deaktivieren",
            "Hält den \"User Choice Protection Driver\" an und setzt ihn auf deaktiviert, damit er keine Registrierungsänderungen blockiert. Windows-Updates können ihn wieder aktivieren.",
            RiskLevel.Mittel, true, true, true,
            "Dienst UCPD (Kernel-Treiber), Starttyp"),

        new(ChangeFeature.DpapiEfsKeys,
            "DPAPI-/EFS-Schlüsselmaterial anpassen (experimentell)",
            "Benennt DPAPI-Masterkey-Dateien um und ersetzt die alte SID darin, damit verschlüsselte Dateien und gespeicherte Kennwörter nutzbar bleiben. Vorher wird eine Sicherung angelegt.",
            RiskLevel.Hoch, false, true, true,
            "C:\\Windows\\System32\\Microsoft\\Protect, %APPDATA%\\Microsoft\\Protect, C:\\ProgramData\\Microsoft\\Crypto"),

        new(ChangeFeature.VaultPreserve,
            "Windows Vault sichern und wiederherstellen",
            "Sichert die Anmeldeinformationsverwaltung (Windows Vault) und die zugehörigen DPAPI-Daten vor der Änderung und spielt sie danach zurück.",
            RiskLevel.Mittel, true, true, false,
            "%APPDATA%\\Microsoft\\Vault, %LOCALAPPDATA%\\Microsoft\\Vault"),

        new(ChangeFeature.OneDriveReset,
            "OneDrive zurücksetzen",
            "Entfernt die OneDrive-Kontobindung, damit Original und Klon nicht mit demselben Konto synchronisieren. Das Konto muss danach neu angemeldet werden.",
            RiskLevel.Mittel, false, true, true,
            "HKLM\\SOFTWARE\\Microsoft\\OneDrive, %LOCALAPPDATA%\\Microsoft\\OneDrive\\settings"),

        new(ChangeFeature.ModernAppsReset,
            "Moderne Apps zurücksetzen",
            "Setzt Appx-Pakete zurück (Filter mit * möglich). Behebt häufige Probleme mit Store-Apps und der Suche nach einer SID-Änderung.",
            RiskLevel.Mittel, false, true, true,
            "Appx-Pakete des angemeldeten Benutzers"),

        new(ChangeFeature.SearchReset,
            "Windows-Suche zurücksetzen",
            "Löscht die Suchdatenbank; Windows baut sie beim ersten Anmelden neu auf (dauert einige Minuten).",
            RiskLevel.Niedrig, true, true, true,
            "C:\\ProgramData\\Microsoft\\Search\\Data"),

        new(ChangeFeature.SqlMaster,
            "SQL-Server-master-Datenbank anpassen",
            "Sichert die master-Datenbank und korrigiert verwaiste Windows-Anmeldungen mit der alten SID. Wird nur ausgeführt, wenn SQL Server gefunden wird.",
            RiskLevel.Hoch, false, true, true,
            "SQL Server: master (sys.server_principals)"),

        new(ChangeFeature.McAfeeId,
            "McAfee-Agent-ID zurücksetzen",
            "Setzt die Agent-GUID des McAfee Agent zurück, damit der Klon als neues Gerät verwaltet wird. Nur wenn McAfee installiert ist.",
            RiskLevel.Niedrig, false, true, false,
            "HKLM\\SOFTWARE\\Network Associates\\ePolicy Orchestrator\\Agent"),

        new(ChangeFeature.DefaultAppsReset,
            "Standard-Apps zurücksetzen",
            "Setzt Dateizuordnungen und Standard-Apps auf die Windows-Vorgaben zurück.",
            RiskLevel.Niedrig, false, true, true,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts, HKCU-Associations"),
    };

    public static FeatureInfo Get(ChangeFeature feature) =>
        All.First(f => f.Feature == feature);

    /// <summary>Bequeme Prüfung: gehört die Aktion zur Standardauswahl?</summary>
    public static bool IsDefaultOn(ChangeFeature feature) => (DefaultFeatures & feature) == feature;
}
