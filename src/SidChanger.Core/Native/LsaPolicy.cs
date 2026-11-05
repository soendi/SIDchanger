using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SidChanger.Core.Native;

/// <summary>
/// Liest die Konto-Domänen-SID (die lokale Computer-SID) über die LSA-Richtlinie.
/// Das funktioniert mit Administratorrechten, ohne die geschützte SAM-Datenbank zu öffnen.
/// </summary>
public static class LsaPolicy
{
    private const uint PolicyViewLocalInformation = 0x00000001;
    private const uint PolicyAccountDomainInformation = 5;

    [StructLayout(LayoutKind.Sequential)]
    private struct LsaUnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LsaObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public int Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PolicyAccountDomainInfo
    {
        public LsaUnicodeString DomainName;
        public IntPtr DomainSid;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint LsaOpenPolicy(IntPtr systemName, ref LsaObjectAttributes objectAttributes,
        uint desiredAccess, out IntPtr policyHandle);

    [DllImport("advapi32.dll")]
    private static extern uint LsaQueryInformationPolicy(IntPtr policyHandle, uint informationClass, out IntPtr buffer);

    [DllImport("advapi32.dll")]
    private static extern uint LsaFreeMemory(IntPtr buffer);

    [DllImport("advapi32.dll")]
    private static extern uint LsaClose(IntPtr policyHandle);

    [DllImport("advapi32.dll")]
    private static extern uint LsaNtStatusToWinError(uint status);

    /// <summary>Liest die Domänen-SID der lokalen Maschine (S-1-5-21-A-B-C).</summary>
    public static bool TryReadAccountDomainSid(out string? value, out string error)
    {
        value = null;
        error = string.Empty;

        var attributes = new LsaObjectAttributes
        {
            Length = Marshal.SizeOf<LsaObjectAttributes>(),
        };

        var status = LsaOpenPolicy(IntPtr.Zero, ref attributes, PolicyViewLocalInformation, out var policy);
        if (status != 0)
        {
            error = $"LSA-Richtlinie nicht lesbar (NTSTATUS 0x{status:X8}, Windows-Fehler {LsaNtStatusToWinError(status)}).";
            return false;
        }

        try
        {
            status = LsaQueryInformationPolicy(policy, PolicyAccountDomainInformation, out var buffer);
            if (status != 0)
            {
                error = $"Domänen-SID nicht abfragbar (NTSTATUS 0x{status:X8}).";
                return false;
            }

            try
            {
                var info = Marshal.PtrToStructure<PolicyAccountDomainInfo>(buffer);
                if (info.DomainSid == IntPtr.Zero)
                {
                    error = "Die LSA-Richtlinie lieferte keine Domänen-SID.";
                    return false;
                }

                value = ToSidString(info.DomainSid);
                if (value is null)
                {
                    error = "Die gelieferte Domänen-SID war nicht lesbar.";
                }

                return value is not null;
            }
            finally
            {
                LsaFreeMemory(buffer);
            }
        }
        finally
        {
            LsaClose(policy);
        }
    }

    /// <summary>Wandelt einen PSID-Zeiger in die Textform S-1-5-21-… um.</summary>
    private static string? ToSidString(IntPtr sid)
    {
        try
        {
            var subAuthorityCount = Marshal.ReadByte(sid, 1);
            var length = 8 + subAuthorityCount * 4;
            var bytes = new byte[length];
            Marshal.Copy(sid, bytes, 0, length);

            return new SecurityIdentifier(bytes, 0).Value;
        }
        catch
        {
            return null;
        }
    }
}
