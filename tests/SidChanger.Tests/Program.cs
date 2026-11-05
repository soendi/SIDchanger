using SidChanger.Sid;

// Kleiner, abhängigkeitsfreier Testläufer für die plattformunabhängige SID-Logik.
// Aufruf: dotnet run --project tests/SidChanger.Tests

var failures = new List<string>();
var passes = 0;

void Check(string name, bool condition, string? detail = null)
{
    if (condition)
    {
        passes++;
        Console.WriteLine($"  OK   {name}");
        return;
    }

    failures.Add(name + (detail is null ? string.Empty : $" ({detail})"));
    Console.WriteLine($"  FAIL {name}{(detail is null ? string.Empty : $" ({detail})")}");
}

Console.WriteLine("MachineSid: Parsen und Formatieren");

Check("gültige SID wird geparst",
    MachineSid.TryParse("S-1-5-21-1111-2222-3333", out var sid, out _) && sid!.Value == "S-1-5-21-1111-2222-3333");

Check("SID mit RID wird abgelehnt",
    !MachineSid.TryParse("S-1-5-21-1111-2222-3333-500", out _, out var ridError) && ridError.Length > 0);

Check("fremdes Präfix wird abgelehnt",
    !MachineSid.TryParse("S-1-5-32-544", out _, out _));

Check("Buchstaben werden abgelehnt",
    !MachineSid.TryParse("S-1-5-21-a-b-c", out _, out _));

Check("alle Sub-Authorities 0 wird abgelehnt",
    !MachineSid.TryParse("S-1-5-21-0-0-0", out _, out _));

Check("leere Eingabe wird abgelehnt",
    !MachineSid.TryParse(null, out _, out _));

Console.WriteLine();
Console.WriteLine("MachineSid: Binärdarstellung");

var testSid = new MachineSid(0xAABBCCDD, 0x11223344, 0x55667788);
var binary = testSid.ToBinary();

Check("Binärlänge ist 24", binary.Length == MachineSid.BinaryLength);
Check("Präfix ist korrekt",
    binary.Take(12).SequenceEqual(new byte[] { 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00 }),
    Convert.ToHexString(binary));
Check("Sub-Authorities sind Little-Endian",
    binary.Skip(12).Take(4).SequenceEqual(new byte[] { 0xDD, 0xCC, 0xBB, 0xAA }),
    Convert.ToHexString(binary));

Check("Rückweg aus Binärdaten",
    MachineSid.TryFromBinary(binary, out var roundTrip) && roundTrip!.Equals(testSid));

Check("RID wird angehängt",
    testSid.WithRid(500) == "S-1-5-21-2864434397-287454020-1432778632-500");

Check("Binärdaten mit RID werden akzeptiert",
    MachineSid.TryFromBinary(binary.Concat(BitConverter.GetBytes(500u)).ToArray(), out var withRid) && withRid!.Equals(testSid));

Console.WriteLine();
Console.WriteLine("SidBinary: Suchen und Ersetzen");

var oldSid = new MachineSid(1, 2, 3);
var newSid = new MachineSid(4, 5, 6);
var oldBytes = oldSid.ToSubAuthorityBytes();
var newBytes = newSid.ToSubAuthorityBytes();

var blob = new byte[] { 0xAA, 0xBB }
    .Concat(oldBytes)
    .Concat(new byte[] { 0x00, 0x01 })
    .Concat(oldBytes)
    .Concat(new byte[] { 0xFF })
    .ToArray();

Check("zwei Vorkommen werden gezählt", SidBinary.Count(blob, oldBytes) == 2);

var patched = (byte[])blob.Clone();
var replaced = SidBinary.ReplaceAll(patched, oldBytes, newBytes);

Check("beide Vorkommen werden ersetzt", replaced == 2);
Check("keine alten Bytes mehr vorhanden", SidBinary.Count(patched, oldBytes) == 0);
Check("neue Bytes sind vorhanden", SidBinary.Count(patched, newBytes) == 2);
Check("Rest des Blobs bleibt unverändert", patched[0] == 0xAA && patched[^1] == 0xFF);

Check("leeres Muster zählt nicht", SidBinary.Count(blob, ReadOnlySpan<byte>.Empty) == 0);
Check("zu kurzer Blob wird ignoriert", SidBinary.Count(new byte[] { 1, 2 }, oldBytes) == 0);

var lengthGuard = false;
try
{
    SidBinary.ReplaceAll(patched, oldBytes, new byte[4]);
}
catch (ArgumentException)
{
    lengthGuard = true;
}

Check("unterschiedliche Längen werden abgelehnt", lengthGuard);

var embedded = new byte[] { 0xDE, 0xAD }
    .Concat(testSid.ToBinary())
    .Concat(new byte[] { 0xBE, 0xEF })
    .ToArray();

Check("Domänen-SID im Blob wird gefunden",
    SidBinary.TryFindDomainSid(embedded, out var found) && found!.Equals(testSid));

Check("Blob ohne SID liefert nichts",
    !SidBinary.TryFindDomainSid(new byte[] { 1, 2, 3, 4 }, out _));

Console.WriteLine();
Console.WriteLine("SidMapping: SIDs umschreiben");

Check("SID mit RID wird umgeschrieben",
    SidMapping.TryMap("S-1-5-21-1-2-3-1001", oldSid, newSid, out var mapped) && mapped == "S-1-5-21-4-5-6-1001",
    mapped);

Check("reine Domänen-SID wird umgeschrieben",
    SidMapping.TryMap("S-1-5-21-1-2-3", oldSid, newSid, out var mappedDomain) && mappedDomain == "S-1-5-21-4-5-6");

Check("fremde SID bleibt unverändert",
    !SidMapping.TryMap("S-1-5-32-544", oldSid, newSid, out var untouched) && untouched == "S-1-5-32-544");

Check("ähnliche, aber fremde SID wird nicht umgeschrieben",
    !SidMapping.TryMap("S-1-5-21-1-2-30-1001", oldSid, newSid, out _));

Check("nicht numerischer Rest wird abgelehnt",
    !SidMapping.TryMap("S-1-5-21-1-2-3-abc", oldSid, newSid, out _));

Check("Zugehörigkeit wird erkannt", SidMapping.BelongsToMachine("S-1-5-21-1-2-3-500", oldSid));
Check("fremde Zugehörigkeit wird verneint", !SidMapping.BelongsToMachine("S-1-5-21-9-9-9-500", oldSid));

Console.WriteLine();
Console.WriteLine("SidStringRewriter: Text-SIDs");

var xml = "<UserId>S-1-5-21-1-2-3-1001</UserId><GroupId>S-1-5-32-544</GroupId>";
var rewrittenXml = SidStringRewriter.Rewrite(xml, oldSid, newSid);

Check("Text-SID wird ersetzt", rewrittenXml.Contains("S-1-5-21-4-5-6-1001"), rewrittenXml);
Check("fremde SID bleibt erhalten", rewrittenXml.Contains("S-1-5-32-544"));
Check("Vorkommen werden gezählt", SidStringRewriter.Count(xml, oldSid) == 1);
Check("Präfix-Treffer ohne RID-Grenze zählt nicht",
    SidStringRewriter.Count("S-1-5-21-1-2-30", oldSid) == 0);
Check("leerer Text bleibt leer", SidStringRewriter.Rewrite(string.Empty, oldSid, newSid) == string.Empty);
Check("Text ohne SID bleibt unverändert",
    SidStringRewriter.Rewrite("keine SID hier", oldSid, newSid) == "keine SID hier");

Console.WriteLine();
Console.WriteLine("ComputerNameRules");

Check("gültiger Name", ComputerNameRules.IsValid("PC-01"));
Check("15 Zeichen sind erlaubt", ComputerNameRules.IsValid("ABCDEFGHIJKLMNO"));
Check("16 Zeichen sind zu lang", !ComputerNameRules.IsValid("ABCDEFGHIJKLMNOP"));
Check("nur Ziffern sind verboten", !ComputerNameRules.IsValid("123456"));
Check("führender Bindestrich ist verboten", !ComputerNameRules.IsValid("-PC"));
Check("Leerzeichen ist verboten", !ComputerNameRules.IsValid("MEIN PC"));
Check("Umlaut ist verboten", !ComputerNameRules.IsValid("BÜRO-PC"));
Check("Normalisierung schreibt groß", ComputerNameRules.Normalize(" pc-01 ") == "PC-01");
Check("Platzhalter ? wird ersetzt",
    ComputerNameRules.ExpandWildcards("PC-??", null).Length == 5);
Check("Platzhalter * setzt MAC ein",
    ComputerNameRules.ExpandWildcards("*", "AABBCCDDEEFF") == "AABBCCDDEEFF");
Check("Ergebnis wird auf 15 Zeichen begrenzt",
    ComputerNameRules.ExpandWildcards("****************", "AABBCCDDEEFF") == "AABBCCDDEEFFAAB");

Console.WriteLine();
Console.WriteLine("SidGenerator");

var generated = Enumerable.Range(0, 500).Select(_ => SidGenerator.CreateRandom()).ToList();

Check("500 SIDs sind eindeutig", generated.Distinct().Count() == 500);
Check("keine SID hat drei Null-Sub-Authorities",
    generated.All(s => !(s.Authority1 == 0 && s.Authority2 == 0 && s.Authority3 == 0)));
Check("SIDs haben gültiges Textformat", generated.All(s => s.Value.StartsWith("S-1-5-21-")));
Check("erzeugte SID lässt sich wieder parsen",
    MachineSid.TryParse(generated[0].Value, out var reparsed, out _) && reparsed!.Equals(generated[0]));

Console.WriteLine();
Console.WriteLine("ChangeRequest: Validierung");

var empty = new ChangeRequest { Features = ChangeFeature.None };
Check("leerer Auftrag ist ungültig", empty.Validate().Count > 0);

var nameWithoutValue = new ChangeRequest
{
    Features = ChangeFeature.MachineSid | ChangeFeature.ComputerName,
    NewSid = new MachineSid(1, 2, 3),
    GenerateRandomSid = false,
};
Check("Namensänderung ohne Namen ist ungültig", nameWithoutValue.Validate().Count > 0);

var aclWithoutProfileList = new ChangeRequest
{
    Features = ChangeFeature.MachineSid | ChangeFeature.ProfileAcl,
    NewSid = new MachineSid(1, 2, 3),
    GenerateRandomSid = false,
};
Check("Profil-ACLs ohne ProfileList sind ungültig", aclWithoutProfileList.Validate().Count > 0);

var valid = new ChangeRequest
{
    Features = FeatureCatalog.DefaultFeatures,
    NewSid = new MachineSid(1, 2, 3),
    GenerateRandomSid = false,
    NewComputerName = "PC-01",
};
Check("Standardauftrag ist gültig", valid.Validate().Count == 0, string.Join("; ", valid.Validate()));

Check("neue SID wird übernommen", valid.ResolveNewSid().Value == "S-1-5-21-1-2-3");
Check("Has() erkennt vorhandene Aktion", valid.Has(ChangeFeature.MachineSid));
Check("Has() verneint fehlende Aktion", !valid.Has(ChangeFeature.GlobalDeviceId));

Console.WriteLine();
Console.WriteLine("FeatureCatalog");

Check("Computer-SID ist Standard", FeatureCatalog.IsDefaultOn(ChangeFeature.MachineSid));
Check("ProfileList ist Standard", FeatureCatalog.IsDefaultOn(ChangeFeature.ProfileList));
Check("globale Geräte-ID ist nicht Standard", !FeatureCatalog.IsDefaultOn(ChangeFeature.GlobalDeviceId));
Check("DPAPI ist nicht Standard", !FeatureCatalog.IsDefaultOn(ChangeFeature.DpapiEfsKeys));
Check("jede Aktion hat einen Katalogeintrag",
    Enum.GetValues<ChangeFeature>()
        .Where(f => f != ChangeFeature.None && !new[] { ChangeFeature.MachineSid }.Contains(f))
        .All(f => FeatureCatalog.All.Any(i => i.Feature == f)));
Check("Katalog enthält keine Duplikate",
    FeatureCatalog.All.Select(i => i.Feature).Distinct().Count() == FeatureCatalog.All.Count);
Check("alle Titel sind deutsch und nicht leer",
    FeatureCatalog.All.All(i => i.Title.Length > 3 && i.Description.Length > 10));

Console.WriteLine();
Console.WriteLine("UCPD-Politik");

var ucpdRunning = new UcpdSnapshot(true, true, false);
var (ucpdPassed, ucpdMessage) = UcpdPolicy.Evaluate(ucpdRunning);

Check("laufender UCPD ist ein Hinweis, keine Sperre", !ucpdPassed && ucpdMessage.Contains("anhalten"));
Check("fehlender UCPD ist unkritisch", UcpdPolicy.Evaluate(new UcpdSnapshot(false, false, false)).Passed);
Check("gestoppter und deaktivierter UCPD ist in Ordnung", UcpdPolicy.Evaluate(new UcpdSnapshot(true, false, true)).Passed);
Check("gestoppter, aber aktiver Starttyp wird erwähnt",
    UcpdPolicy.Evaluate(new UcpdSnapshot(true, false, false)).Message.Contains("Starttyp"));

var ucpdStopped = UcpdPolicy.DescribeStop(ucpdRunning, true, true);
Check("angehalten und deaktiviert braucht keinen Neustart",
    ucpdStopped.Stopped && ucpdStopped.Disabled && !ucpdStopped.RebootRequired);

var ucpdReboot = UcpdPolicy.DescribeStop(ucpdRunning, false, true);
Check("nur deaktiviert verlangt einen Neustart",
    !ucpdReboot.Stopped && ucpdReboot.Disabled && ucpdReboot.RebootRequired);

var ucpdFailed = UcpdPolicy.DescribeStop(ucpdRunning, false, false);
Check("ohne Erfolg bleibt ein erklärender Hinweis",
    !ucpdFailed.Stopped && !ucpdFailed.Disabled && ucpdFailed.Message.Contains("Administrator"));

var ucpdMissing = UcpdPolicy.DescribeStop(new UcpdSnapshot(false, false, false), false, false);
Check("nicht vorhandener Treiber meldet keine Änderung",
    !ucpdMissing.Stopped && !ucpdMissing.Disabled && ucpdMissing.Message.Contains("nicht vorhanden"));

Console.WriteLine();
Console.WriteLine(new string('-', 60));
Console.WriteLine($"{passes} Tests bestanden, {failures.Count} fehlgeschlagen.");

if (failures.Count > 0)
{
    Console.WriteLine();
    foreach (var failure in failures)
    {
        Console.WriteLine("FEHLER: " + failure);
    }

    return 1;
}

return 0;
