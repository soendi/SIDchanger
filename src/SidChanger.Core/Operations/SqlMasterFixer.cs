using Microsoft.Win32;
using SidChanger.Core.Operations;
using SidChanger.Sid;

namespace SidChanger.Core.Operations;

/// <summary>Gefundene SQL-Server-Installation.</summary>
public sealed record SqlServerInfo(string InstanceName, string SqlCmdPath)
{
    public string ServerArgument => string.IsNullOrEmpty(InstanceName) ? "." : @".\" + InstanceName;
}

/// <summary>
/// Sichert die master-Datenbank eines lokalen SQL Servers und erzeugt ein Skript,
/// das verwaiste Windows-Anmeldungen (alte SID) neu anlegt. Das Skript wird bewusst
/// nicht automatisch ausgeführt, weil beim Neuanlegen von Anmeldungen
/// Berechtigungen verloren gehen können.
/// </summary>
public static class SqlMasterFixer
{
    /// <summary>Sucht eine lokale SQL-Server-Instanz und sqlcmd.exe.</summary>
    public static SqlServerInfo? Detect(Action<string>? warn)
    {
        var instances = new List<string>();

        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL");
            if (key is not null)
            {
                instances.AddRange(key.GetValueNames());
            }
        }
        catch (Exception ex)
        {
            warn?.Invoke($"SQL-Instanzen nicht lesbar: {ex.Message}");
        }

        if (instances.Count == 0)
        {
            return null;
        }

        var sqlCmd = FindSqlCmd(warn);
        if (sqlCmd is null)
        {
            warn?.Invoke("SQL Server gefunden, aber sqlcmd.exe nicht. Bitte die Client Tools installieren.");
            return null;
        }

        // Standardinstanz bevorzugen, sonst die erste gefundene.
        var instance = instances.FirstOrDefault(i => i.Equals("MSSQLSERVER", StringComparison.OrdinalIgnoreCase))
                       ?? instances[0];

        var name = instance.Equals("MSSQLSERVER", StringComparison.OrdinalIgnoreCase) ? string.Empty : instance;
        return new SqlServerInfo(name, sqlCmd);
    }

    private static string? FindSqlCmd(Action<string>? warn)
    {
        var (exitCode, output) = Shell.Run("cmd.exe", "/c where sqlcmd", 30_000);
        if (exitCode == 0 && !string.IsNullOrWhiteSpace(output))
        {
            var first = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim();
            if (!string.IsNullOrEmpty(first) && File.Exists(first))
            {
                return first;
            }
        }

        var candidates = new[]
        {
            @"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\180\Tools\Binn\SQLCMD.EXE",
            @"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE",
            @"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\130\Tools\Binn\SQLCMD.EXE",
            @"C:\Program Files\Microsoft SQL Server\110\Tools\Binn\SQLCMD.EXE",
            @"C:\Program Files\Microsoft SQL Server\120\Tools\Binn\SQLCMD.EXE",
            @"C:\Program Files\Microsoft SQL Server\130\Tools\Binn\SQLCMD.EXE",
            @"C:\Program Files\Microsoft SQL Server\140\Tools\Binn\SQLCMD.EXE",
            @"C:\Program Files\Microsoft SQL Server\150\Tools\Binn\SQLCMD.EXE",
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    /// <summary>
    /// Sichert master und legt ein Reparaturskript ab. Liefert (Erfolg, Meldung).
    /// </summary>
    public static (bool Success, string Message) BackupAndCreateScript(
        SqlServerInfo server,
        MachineSid oldSid,
        string backupDirectory,
        Action<string> log,
        Action<string>? warn,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var backupFile = Path.Combine(backupDirectory, "master_sicherung.bak");
        var scriptFile = Path.Combine(backupDirectory, "sql_master_reparatur.sql");
        var logFile = Path.Combine(backupDirectory, "sql_master_reparatur.log");
        var tempScript = Path.Combine(Path.GetTempPath(), "sidchanger_sql_" + Guid.NewGuid().ToString("N") + ".sql");

        var sidHex = "0x" + Convert.ToHexString(oldSid.ToBinary());

        var backupSql = $"""
            SET NOCOUNT ON;
            BACKUP DATABASE master TO DISK = N'{backupFile}' WITH INIT, COPY_ONLY;
            PRINT 'Sicherung erstellt: {backupFile}';
            SELECT 'VERWAIST: ' + name + ' / ' + CONVERT(varchar(200), sid, 1)
            FROM sys.server_principals
            WHERE type IN ('U','G') AND SUBSTRING(sid, 1, 24) = {sidHex};
            """;

        var fixSql = $"""
            -- Reparaturskript für verwaiste Windows-Anmeldungen nach einer SID-Änderung.
            -- Alte Computer-SID: {oldSid.Value}
            -- ACHTUNG: Anmeldungen werden gelöscht und neu angelegt. Serverweite
            -- Berechtigungen und Rollenmitgliedschaften müssen danach neu gesetzt werden!
            -- Vor der Ausführung die master-Sicherung prüfen: master_sicherung.bak
            SET NOCOUNT ON;
            DECLARE @name sysname, @sql nvarchar(max) = N'', @cmd nvarchar(max);
            DECLARE cur CURSOR LOCAL FAST_FORWARD FOR
                SELECT name FROM sys.server_principals
                WHERE type IN ('U','G') AND SUBSTRING(sid, 1, 24) = {sidHex} AND name NOT LIKE '##%';
            OPEN cur;
            FETCH NEXT FROM cur INTO @name;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @cmd = N'DROP LOGIN ' + QUOTENAME(@name) + N'; CREATE LOGIN ' + QUOTENAME(@name) + N' FROM WINDOWS;';
                PRINT @cmd;
                BEGIN TRY
                    EXEC sp_executesql @cmd;
                END TRY
                BEGIN CATCH
                    PRINT 'FEHLER bei ' + @name + ': ' + ERROR_MESSAGE();
                END CATCH
                FETCH NEXT FROM cur INTO @name;
            END
            CLOSE cur;
            DEALLOCATE cur;
            PRINT 'Fertig. Bitte Rollen und Berechtigungen prüfen (sp_validatelogins).';
            """;

        try
        {
            File.WriteAllText(tempScript, backupSql);
            File.WriteAllText(scriptFile, fixSql);

            var arguments = $"-S {server.ServerArgument} -E -b -i \"{tempScript}\" -o \"{logFile}\"";
            var (exitCode, output) = Shell.Run(server.SqlCmdPath, arguments, 300_000);

            if (exitCode == 0)
            {
                log($"master-Datenbank gesichert: {backupFile}");
                log($"Reparaturskript erstellt: {scriptFile}");

                var report = File.Exists(logFile) ? File.ReadAllText(logFile).Trim() : output;
                foreach (var line in report.Split('\n', StringSplitOptions.RemoveEmptyEntries).Where(l => l.Contains("VERWAIST")))
                {
                    warn?.Invoke(line.Trim());
                }

                return (true,
                    $"master gesichert ({Path.GetFileName(backupFile)}). Reparaturskript für verwaiste Anmeldungen liegt unter {scriptFile} – bitte prüfen und manuell ausführen.");
            }

            return (false, $"sqlcmd meldete Fehler (Exitcode {exitCode}): {output}");
        }
        catch (Exception ex)
        {
            return (false, $"SQL-Bearbeitung fehlgeschlagen: {ex.Message}");
        }
        finally
        {
            try
            {
                File.Delete(tempScript);
            }
            catch
            {
                // temporäre Datei darf bleiben
            }
        }
    }
}
