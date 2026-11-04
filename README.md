# SID-Wechsler

Grafisches Windows-Werkzeug (C# / WPF, deutsch) zum Ändern der **lokalen Computer-SID**,
des Computernamens und der übrigen Gerätekennungen – ohne Windows neu zu installieren.
Es bildet die Funktionen von [SIDCHG](https://www.stratesave.com/html/sidchg.html) in einer
Oberfläche ab, in der jede Einzelaktion einzeln ausgewählt werden kann.

> **Wichtig:** Nur auf eigenen, geklonten Rechnern oder Images verwenden. Eine SID-Änderung
> greift tief in Registrierung und Dateisystem ein. Vorher Sicherung anlegen, Virenscanner
> deaktivieren, BitLocker aussetzen, andere Benutzer abmelden. Die Änderung niemals abbrechen.

---

## Was das Programm ändert

| Aktion | Ort / Wirkung | Standard |
|---|---|---|
| Computer-SID ersetzen | `HKLM\SAM\SAM` und `HKLM\SECURITY`: alle Vorkommen der 24-Byte-Domänen-SID werden durch eine neue Zufalls-SID ersetzt, anschließend wird die neue SID aus `Domains\Account\V` zurückgelesen und verifiziert | ✅ |
| Benutzerprofile umschlüsseln | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-…` wird auf die neue SID umbenannt | ✅ |
| NTFS-Rechte der Profile | Besitzer, DACL und SACL der Profilordner werden von der alten auf die neue SID umgeschrieben (optional rekursiv) | ✅ |
| Taskplaner | SID in Aufgaben-XML (`System32\Tasks`) und im `TaskCache` | ✅ |
| WSUS-ID | `SusClientId`, `PingID` neu, `SusClientIdValidation` gelöscht | ✅ |
| MachineGuid | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` | ✅ |
| Machine ID (SQM) | `HKLM\SOFTWARE\Microsoft\SQMClient\MachineId` | ✅ |
| Geräte-ID moderner Apps | `…\CurrentVersion\Store\DeviceId`, `…\CurrentVersion\Appx\DeviceId`, `…\AppModel\Deployment\DeviceId`, `HwProfileGuid` – nur vorhandene Werte | ✅ |
| Globale Geräte-ID | `…\Store\GlobalDeviceId` (kann die Aktivierung beeinflussen) | ❌ |
| MSDTC-CID | `HKLM\SOFTWARE\Microsoft\MSDTC\CID` | ✅ |
| DHCPv6-DUID | Wert löschen, Windows erzeugt beim Start eine neue | ✅ |
| Info-Center | Benachrichtigungseinstellungen zurücksetzen | ✅ |
| DPAPI/EFS | Masterkeys sichern, SID-benannte Ordner umbenennen, SID-Bytes in Schlüsseldateien ersetzen, ACLs anpassen (experimentell) | ❌ |
| Windows Vault | Anmeldeinformationsverwaltung vorher sichern, danach zurückspielen | ✅ |
| OneDrive | Kontobindung und lokale Einstellungen entfernen | ❌ |
| Moderne Apps | `Reset-AppxPackage` mit Filter (`*`, `-App*`) | ❌ |
| Windows-Suche | Suchdatenbank löschen (Neuaufbau beim Anmelden) | ✅ |
| SQL Server master | Sicherung + Reparaturskript für verwaiste Anmeldungen (siehe Hinweis unten) | ❌ |
| McAfee-Agent-ID | `AgentGUID` ersetzen, falls vorhanden | ❌ |
| Standard-Apps | Dateizuordnungen des Benutzers zurücksetzen | ❌ |
| Computername / -beschreibung | `Rename-Computer` plus Registry-Werte, Platzhalter `?` und `*` | ❌ |

**Reihenfolge eines Laufs:** Vorbereitung (Sicherungen) → Änderung → Abschluss
(Vault/DPAPI wiederherstellen) → optionaler Neustart/Herunterfahren.

---

## Oberfläche

* **Linke Spalte:** aktuelle und neue SID, Computername/-beschreibung, alle Aktionen als
  einzeln abwählbare Karten mit Risikokennzeichnung, erweiterte Optionen
  (Neustartverhalten, rekursive ACLs, App-Filter).
* **Rechte Spalte:** Ergebnisse der Vorabprüfung (Administratorrechte, Domäne, Virenscanner,
  ausstehende Updates, BitLocker, UCPD-Treiber, Windows-Version), Schritt-für-Schritt-Status
  und ein vollständiges Protokoll (speicherbar).
* **Schaltflächen:** Analyse (ändert nichts), Änderungen anwenden (mit Bestätigungsdialog),
  letzte Änderung zurücknehmen, Sicherungsordner öffnen.

---

## Voraussetzungen

* Windows 10/11 oder Windows Server 2016–2025 (x64/ARM64), .NET 8.
* Administratorrechte – das Manifest erzwingt `requireAdministrator`.
* Vor der Änderung: Virenscanner-Echtzeitschutz aus, BitLocker aussetzen
  (`manage-bde -protectors -disable C: -RebootCount 1`), andere Benutzer abmelden,
  keine ausstehenden Windows-Updates.
* Kein Domänencontroller, kein domänenbeigetretener Rechner ohne Bereitschaft zum erneuten Join.

---

## Bauen

```powershell
# Windows, mit installiertem .NET 8 SDK
dotnet build SidChanger.sln -c Release
dotnet run --project src/SidChanger.App

# eigenständige EXE
dotnet publish src/SidChanger.App -c Release -r win-x64 --self-contained false
```

Auf Linux/macOS lässt sich das Projekt ebenfalls kompilieren (Cross-Targeting):

```bash
dotnet build SidChanger.sln -c Release -p:EnableWindowsTargeting=true
```

Tests der plattformunabhängigen SID-Logik:

```bash
dotnet run --project tests/SidChanger.Tests
```

Es werden **keine NuGet-Pakete** benötigt.

---

## Sicherung und Rücknahme

Vor jeder Änderung entsteht `C:\ProgramData\SidChanger\Backups\<Zeitstempel>\`:

* `sicherung.json` – alle geänderten Registrierungswerte (Binärwerte als Base64) und
  die ursprünglichen ACLs (SDDL),
* `protokoll.txt` – vollständiges Protokoll,
* `vault\`, `dpapi\` – gesicherte Verschlüsselungsdaten (wenn aktiviert),
* `master_sicherung.bak`, `sql_master_reparatur.sql` (wenn SQL Server gefunden wurde).

`C:\ProgramData\SidChanger\letzter-lauf.json` speichert alte/neue SID. Über
**„Letzte Änderung zurücknehmen“** werden SID, Profilzuordnungen, Profilrechte und die
gesicherten Registrierungswerte zurückgesetzt (Neustart erforderlich).

---

## Bewusste Unterschiede zu SIDCHG

1. **SIDCHG ist kostenpflichtig lizenziert.** Dieses Programm ist eine eigene,
   unabhängige Implementierung ohne Lizenzschlüssel und ohne Bezug zu Stratesave.
2. **SQL Server:** Das master-Backup und ein Reparaturskript werden erzeugt, das Skript wird
   aber **nicht automatisch ausgeführt**. Beim Neuanlegen von Anmeldungen können
   serverweite Berechtigungen verloren gehen – das soll niemand unbeabsichtigt auslösen.
   Skript prüfen, dann mit `sqlcmd -S . -E -i sql_master_reparatur.sql` ausführen.
3. **Alles online, kein Hintergrundprozess.** Es gibt keine Ausführung aus Windows PE und
   keine „Run Once“-Nachverarbeitung für angemeldete Benutzer. Die Änderung läuft
   vollständig in einem Durchgang; danach ist ein Neustart nötig.
4. **Geräte-IDs moderner Apps:** Diese Werte sind nicht offiziell dokumentiert. Es werden
   nur vorhandene, bekannte Registrierungswerte geändert – nichts wird erfunden.
5. **DPAPI/EFS** ist als experimentell gekennzeichnet und standardmäßig aus, weil
   Schlüsselmaterial je nach Windows-Version unterschiedlich aufgebaut ist.
6. **Keine Lizenz-/Aktivierungsänderung.** Eine SID-Änderung beeinflusst die
   Windows-Lizenzierung nicht; für Image-Klone ggf. zusätzlich `slmgr -rearm` nutzen.

---

## Nach der Änderung

* Neustart **nicht** unterbrechen, nicht anmelden, bis Windows neu gestartet ist.
* Danach prüfen: Anmeldung, Benutzerprofil, Drucker, Domäne (neu beitreten),
  WSUS-Registrierung, OneDrive-Konto, Store-Apps (ggf. „Moderne Apps zurücksetzen“).
* Hängen gebliebene Netzlaufwerke mit `NET USE Laufwerk: /DELETE` entfernen.
* Suchindizierung braucht nach dem Reset einige Minuten.

---

## Projektstruktur

```
src/SidChanger.Sid/    plattformunabhängige SID-Logik (Parsen, Bytes, ACL-Mapping, Regeln)
src/SidChanger.Core/   Windows-Schicht: Privilegien, SAM/SECURITY, Profile, ACLs, Aktionen, Engine
src/SidChanger.App/    WPF-Oberfläche (deutsch), ViewModels, Manifest mit Adminrechten
tests/SidChanger.Tests kleiner Testläufer ohne externe Abhängigkeiten
```

Die Engine ist von der Oberfläche getrennt und lässt sich auch ohne WPF verwenden
(`ChangeEngine`, `ChangeRequest`, `StepCatalog`).
