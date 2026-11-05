namespace SidChanger.Sid;

/// <summary>
/// Abhängigkeiten zwischen den Aktionen. Ein SID-Wechsel zerstört die Zuordnung von Profilen
/// und Aufgaben zur alten SID – deshalb gehören diese Schritte zwingend dazu. Die Regeln liegen
/// hier (ohne Windows-Bezug), damit Oberfläche und Tests dieselbe Logik verwenden.
/// </summary>
public static class FeatureDependencies
{
    /// <summary>
    /// Voraussetzungen: eine Aktion ist nur sinnvoll, wenn die angegebene Aktion mitläuft.
    /// </summary>
    public static IReadOnlyDictionary<ChangeFeature, ChangeFeature> Prerequisites { get; } =
        new Dictionary<ChangeFeature, ChangeFeature>
        {
            [ChangeFeature.ProfileList] = ChangeFeature.MachineSid,
            [ChangeFeature.ProfileAcl] = ChangeFeature.ProfileList,
            [ChangeFeature.TaskScheduler] = ChangeFeature.MachineSid,
            [ChangeFeature.DpapiEfsKeys] = ChangeFeature.MachineSid,
        };

    /// <summary>
    /// Pflichtbegleiter: wird die Aktion gewählt, müssen diese Aktionen mitlaufen,
    /// damit das System danach wieder funktioniert.
    /// </summary>
    public static IReadOnlyDictionary<ChangeFeature, ChangeFeature> Companions { get; } =
        new Dictionary<ChangeFeature, ChangeFeature>
        {
            [ChangeFeature.MachineSid] =
                ChangeFeature.ProfileList | ChangeFeature.ProfileAcl | ChangeFeature.TaskScheduler,
        };

    /// <summary>Prüft, ob eine einzelne Aktion in einer Auswahl enthalten ist.</summary>
    public static bool Has(ChangeFeature selected, ChangeFeature feature) => (selected & feature) == feature;

    /// <summary>
    /// Erweitert eine Auswahl um alle Voraussetzungen und Pflichtbegleiter (transitiv).
    /// </summary>
    public static ChangeFeature Expand(ChangeFeature selected)
    {
        var result = selected;

        bool changed;
        do
        {
            changed = false;

            foreach (var (feature, required) in Prerequisites)
            {
                if (Has(result, feature) && !Has(result, required))
                {
                    result |= required;
                    changed = true;
                }
            }

            foreach (var (feature, companions) in Companions)
            {
                if (Has(result, feature) && (result & companions) != companions)
                {
                    result |= companions;
                    changed = true;
                }
            }
        } while (changed);

        return result;
    }

    /// <summary>
    /// Entfernt eine Aktion samt allem, was ohne sie nicht mehr möglich ist (Kaskade nach unten).
    /// </summary>
    public static ChangeFeature RemoveWith(ChangeFeature selected, ChangeFeature removed)
    {
        var result = selected & ~removed;

        bool changed;
        do
        {
            changed = false;

            foreach (var (feature, required) in Prerequisites)
            {
                if (Has(result, feature) && !Has(result, required))
                {
                    result &= ~feature;
                    changed = true;
                }
            }
        } while (changed);

        return result;
    }

    /// <summary>
    /// Wird die Aktion nur mitgesetzt, weil eine andere Aktion sie verlangt?
    /// Solche Haken sind in der Oberfläche gesperrt, damit kein unbrauchbarer Zustand entsteht.
    /// </summary>
    public static bool IsForcedByOthers(ChangeFeature selected, ChangeFeature feature)
    {
        // Der SID-Wechsel ist der Ausgangspunkt der ganzen Kette und bleibt immer abwählbar –
        // sonst ließe sich ein einmal gesetzter Haken nie wieder lösen. Wer ihn abwählt,
        // verliert die abhängigen Haken automatisch mit.
        if (feature == ChangeFeature.MachineSid || !Has(selected, feature))
        {
            return false;
        }

        foreach (var (other, companions) in Companions)
        {
            if (other != feature && Has(selected, other) && Has(companions, feature))
            {
                return true;
            }
        }

        foreach (var (other, required) in Prerequisites)
        {
            if (other != feature && Has(selected, other) && Has(required, feature))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Fehlende Voraussetzungen und Pflichtbegleiter einer Auswahl als verständliche Meldungen.
    /// </summary>
    public static IReadOnlyList<string> Missing(ChangeFeature selected)
    {
        var errors = new List<string>();

        foreach (var (feature, required) in Prerequisites)
        {
            if (Has(selected, feature) && !Has(selected, required))
            {
                errors.Add($"„{Title(feature)}“ setzt „{Title(required)}“ voraus.");
            }
        }

        foreach (var (feature, companions) in Companions)
        {
            if (!Has(selected, feature))
            {
                continue;
            }

            var lacking = All(companions).Where(c => !Has(selected, c)).Select(Title).ToList();
            if (lacking.Count > 0)
            {
                errors.Add($"„{Title(feature)}“ erfordert zusätzlich: {string.Join(", ", lacking)}.");
            }
        }

        return errors;
    }

    /// <summary>Alle Einzelaktionen, die in einer Bitmaske stecken.</summary>
    public static IReadOnlyList<ChangeFeature> All(ChangeFeature mask) =>
        FeatureCatalog.All.Select(i => i.Feature).Where(f => Has(mask, f)).ToList();

    private static string Title(ChangeFeature feature) =>
        FeatureCatalog.All.FirstOrDefault(i => i.Feature == feature)?.Title ?? feature.ToString();
}
