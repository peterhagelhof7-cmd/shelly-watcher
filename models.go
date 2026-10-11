package main

//go:generate go run ./tools/genmodels models_gen.go

import "strings"

type modelInfo struct {
	Name string
	Gen  int
}

// extraModels ergänzt Codes, die in aioshelly (noch) fehlen. Einträge hier
// haben Vorrang vor knownModels.
var extraModels = map[string]modelInfo{}

// sleepyModels sind Akku-/Batteriegeräte, die die meiste Zeit schlafen und
// daher nur sporadisch erreichbar sind. Wird zusätzlich dynamisch über
// Batteriewerte im Status erkannt.
var sleepyModels = map[string]bool{
	"SHHT-1": true, "SHDW-1": true, "SHDW-2": true, "SHWT-1": true,
	"SHSM-01": true, "SHSM-02": true, "SHBTN-1": true, "SHBTN-2": true,
	"SNSN-0013A": true, "SNSN-0031Z": true, "S3SN-0U12A": true,
	"S3SN-1U12A": true, "S4SN-0071A": true, "S4SN-0071Z": true,
}

// modelName liefert einen lesbaren Namen für einen Modell-/Typcode. app ist
// das "app"-Feld der Gen2+-Geräte (z.B. "Plus1PM") und dient als Fallback.
func modelName(code, app string) string {
	if m, ok := extraModels[code]; ok {
		return m.Name
	}
	if m, ok := knownModels[code]; ok {
		return m.Name
	}
	if app != "" {
		return "Shelly " + splitCamel(app)
	}
	return ""
}

// splitCamel macht aus "PlusPlugS" -> "Plus Plug S", "Pro4PM" bleibt lesbar.
func splitCamel(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			prev := rune(s[i-1])
			if prev >= 'a' && prev <= 'z' {
				b.WriteByte(' ')
			}
		}
		b.WriteRune(r)
	}
	return b.String()
}
