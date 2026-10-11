package main

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Detail sind Schaltzustände und Messwerte eines Geräts, generationsübergreifend
// vereinheitlicht. Wird bei jedem Poll aus dem ohnehin gelesenen Status
// gebildet (keine Zusatzabfrage) und für die Detailseite live aufgefrischt.
type Detail struct {
	Components []Component `json:"components"`
	CloudOn    *bool       `json:"cloud_enabled,omitempty"`
	CloudConn  *bool       `json:"cloud_connected,omitempty"`
	CloudSrv   string      `json:"cloud_server,omitempty"`
	At         time.Time   `json:"at"`
}

// Component ist ein Kanal (Schalter, Rollladen, Messgerät, Sensor …).
type Component struct {
	Kind   string  `json:"kind"` // switch, cover, light, input, em, temperature, sensor …
	ID     int     `json:"id"`
	Name   string  `json:"name,omitempty"`
	On     *bool   `json:"on,omitempty"`    // Schaltzustand bzw. Eingang aktiv
	State  string  `json:"state,omitempty"` // z.B. Rollladen "open"/"stop"
	Values []Value `json:"values,omitempty"`
}

type Value struct {
	Label string `json:"label"`
	V     any    `json:"v"`
	Unit  string `json:"unit,omitempty"`
}

// ---- Gen2+ ----

// Systemkomponenten, die keine Kanäle/Messwerte sind.
var gen2Meta = map[string]bool{
	"sys": true, "wifi": true, "cloud": true, "mqtt": true, "ble": true, "ws": true, "eth": true,
	"ui": true, "knx": true, "matter": true, "bthome": true, "script": true, "modbus": true,
	"zigbee": true, "plugs_ui": true, "wd_ui": true, "ht_ui": true, "schedule": true, "webhook": true,
	"kvs": true, "sensoraddon": true, "service": true, "lora": true,
}

type fieldInfo struct {
	label, unit string
	scale       float64 // Faktor auf den Rohwert (0 = 1)
}

// Bekannte Felder der Gen2+-Komponenten. Präfixe a_/b_/c_ (Phasen) werden
// generisch behandelt.
var gen2Fields = map[string]fieldInfo{
	"apower": {"Leistung", "W", 0}, "act_power": {"Wirkleistung", "W", 0}, "aprt_power": {"Scheinleistung", "VA", 0},
	"voltage": {"Spannung", "V", 0}, "current": {"Strom", "A", 0}, "freq": {"Frequenz", "Hz", 0},
	"pf": {"Leistungsfaktor", "", 0}, "aenergy.total": {"Energie gesamt", "kWh", 0.001},
	"ret_aenergy.total": {"Einspeisung gesamt", "kWh", 0.001},
	"total_act_power":   {"Gesamtleistung", "W", 0}, "total_aprt_power": {"Gesamt-Scheinleistung", "VA", 0},
	"total_current": {"Gesamtstrom", "A", 0}, "n_current": {"Strom N", "A", 0},
	"total_act": {"Energie gesamt", "kWh", 0.001}, "total_act_ret": {"Einspeisung gesamt", "kWh", 0.001},
	"total_act_energy": {"Energie gesamt", "kWh", 0.001}, "total_act_ret_energy": {"Einspeisung gesamt", "kWh", 0.001},
	"temperature.tC": {"Temperatur", "°C", 0}, "tC": {"Temperatur", "°C", 0}, "rh": {"Luftfeuchte", "%", 0},
	"lux": {"Helligkeit", "lx", 0}, "illumination": {"Lichtstärke", "", 0}, "brightness": {"Helligkeit", "%", 0},
	"current_pos": {"Position", "%", 0}, "target_pos": {"Zielposition", "%", 0},
	"battery.percent": {"Batterie", "%", 0}, "battery.V": {"Batteriespannung", "V", 0},
	"external.present": {"Netzteil angeschlossen", "", 0}, "alarm": {"Alarm", "", 0}, "mute": {"Stumm", "", 0},
	"percent": {"Wert", "%", 0}, "xpercent": {"Wert", "%", 0}, "counts.total": {"Impulse gesamt", "", 0},
	"freq.value": {"Frequenz", "Hz", 0}, "value": {"Wert", "", 0}, "white": {"Weiß", "", 0},
	"timer_remaining": {"Timer verbleibend", "s", 0}, "overtemp": {"Übertemperatur", "", 0},
	"move_timeout": {"Fahrzeit-Limit", "s", 0}, "last_direction": {"Letzte Richtung", "", 0},
	"num_objects": {"Objekte", "", 0}, "temp": {"Temperatur", "°C", 0},
}

// Felder, die nur Lärm wären.
var gen2Skip = map[string]bool{
	"id": true, "source": true, "minute_ts": true, "tF": true, "temperature.tF": true, "aenergy.minute_ts": true,
	"ret_aenergy.minute_ts": true, "output": true, "state": true, "flags": true, "user_calibrated_phase": true,
}

var phaseNames = map[string]string{"a_": "L1 ", "b_": "L2 ", "c_": "L3 "}

func gen2Components(raw json.RawMessage) []Component {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	var out []Component
	for key, body := range m {
		kind, idStr, _ := strings.Cut(key, ":")
		if gen2Meta[kind] {
			continue
		}
		var fields map[string]any
		if json.Unmarshal(body, &fields) != nil {
			continue
		}
		id, _ := strconv.Atoi(idStr)
		c := Component{Kind: kind, ID: id}
		if b, ok := fields["output"].(bool); ok {
			c.On = &b
		}
		switch st := fields["state"].(type) {
		case bool:
			c.On = &st
		case string:
			c.State = st
		}
		flatten("", fields, &c)
		sortValues(c.Values)
		out = append(out, c)
	}
	sortComponents(out)
	return out
}

func flatten(prefix string, fields map[string]any, c *Component) {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		full := prefix + k
		if gen2Skip[full] || gen2Skip[k] && prefix == "" {
			continue
		}
		switch v := fields[k].(type) {
		case map[string]any:
			if prefix == "" { // eine Ebene tief, z.B. aenergy.total, temperature.tC
				flatten(full+".", v, c)
			}
		case []any:
			if k == "errors" && len(v) > 0 {
				c.Values = append(c.Values, Value{"Fehler", fmt.Sprint(v...), ""})
			}
		case nil:
		default:
			c.Values = append(c.Values, labelValue(full, v))
		}
	}
}

// Reihenfolge der Messwerte: Summen vor Phasen, innerhalb davon Leistung,
// Spannung, Strom … und Unbekanntes zuletzt.
var labelRank = map[string]int{
	"Gesamtleistung": 1, "Leistung": 2, "Wirkleistung": 2, "Scheinleistung": 3, "Gesamt-Scheinleistung": 3,
	"Spannung": 4, "Strom": 5, "Gesamtstrom": 5, "Strom N": 6, "Leistungsfaktor": 7, "Frequenz": 8,
	"Energie gesamt": 9, "Einspeisung gesamt": 10, "Position": 11, "Zielposition": 12, "Helligkeit": 13,
	"Temperatur": 14, "Luftfeuchte": 15, "Batterie": 16, "Batteriespannung": 17, "Fehler": 99,
}

func sortValues(vs []Value) {
	rank := func(l string) (int, int) {
		phase := 0
		for i, p := range []string{"L1 ", "L2 ", "L3 "} {
			if strings.HasPrefix(l, p) {
				phase, l = i+1, strings.TrimPrefix(l, p)
			}
		}
		r, ok := labelRank[l]
		if !ok {
			r = 50
		}
		return phase, r
	}
	sort.SliceStable(vs, func(i, j int) bool {
		pi, ri := rank(vs[i].Label)
		pj, rj := rank(vs[j].Label)
		if pi != pj {
			return pi < pj
		}
		return ri < rj
	})
}

func labelValue(key string, v any) Value {
	phase := ""
	for p, name := range phaseNames {
		if strings.HasPrefix(key, p) {
			phase, key = name, strings.TrimPrefix(key, p)
		}
	}
	fi, ok := gen2Fields[key]
	if !ok {
		return Value{phase + key, v, ""}
	}
	if f, isNum := v.(float64); isNum && fi.scale != 0 {
		v = round(f*fi.scale, 3)
	}
	return Value{phase + fi.label, v, fi.unit}
}

func round(f float64, n int) float64 {
	p := math.Pow(10, float64(n))
	return math.Round(f*p) / p
}

var kindOrder = map[string]int{
	"switch": 1, "light": 2, "rgb": 2, "rgbw": 2, "cct": 2, "rgbcct": 2, "cover": 3, "pm1": 4, "em": 5,
	"emdata": 6, "em1": 5, "em1data": 6, "input": 7, "temperature": 8, "humidity": 9, "illuminance": 10,
	"devicepower": 20,
}

func sortComponents(cs []Component) {
	sort.SliceStable(cs, func(i, j int) bool {
		oi, oj := kindOrder[cs[i].Kind], kindOrder[cs[j].Kind]
		if oi == 0 {
			oi = 15
		}
		if oj == 0 {
			oj = 15
		}
		if oi != oj {
			return oi < oj
		}
		if cs[i].Kind != cs[j].Kind {
			return cs[i].Kind < cs[j].Kind
		}
		return cs[i].ID < cs[j].ID
	})
}

// gen2Config liefert Kanalnamen und Cloud-Einstellungen aus Shelly.GetConfig.
func gen2Config(raw json.RawMessage) (names map[string]string, cloudOn *bool, server string) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil, nil, ""
	}
	names = map[string]string{}
	for key, body := range m {
		var c struct {
			Name   *string `json:"name"`
			Enable *bool   `json:"enable"`
			Server *string `json:"server"`
		}
		if json.Unmarshal(body, &c) != nil {
			continue
		}
		if key == "cloud" {
			cloudOn = c.Enable
			if c.Server != nil {
				server = *c.Server
			}
			continue
		}
		if c.Name != nil && *c.Name != "" && strings.Contains(key, ":") {
			names[key] = *c.Name
		}
	}
	return names, cloudOn, server
}

// ---- Gen1 ----

type gen1Raw struct {
	Relays []struct {
		IsOn      bool `json:"ison"`
		Overpower bool `json:"overpower"`
	} `json:"relays"`
	Meters []struct {
		Power   *float64 `json:"power"`
		Total   *float64 `json:"total"` // Wattminuten
		IsValid *bool    `json:"is_valid"`
	} `json:"meters"`
	EMeters []struct {
		Power   *float64 `json:"power"`
		Voltage *float64 `json:"voltage"`
		Current *float64 `json:"current"`
		PF      *float64 `json:"pf"`
		Total   *float64 `json:"total"` // Wh
		TotalRe *float64 `json:"total_returned"`
	} `json:"emeters"`
	Inputs []struct {
		Input int    `json:"input"`
		Event string `json:"event"`
	} `json:"inputs"`
	Lights []struct {
		IsOn       bool     `json:"ison"`
		Brightness *float64 `json:"brightness"`
		Mode       string   `json:"mode"`
		Power      *float64 `json:"power"`
	} `json:"lights"`
	Rollers []struct {
		State      string   `json:"state"`
		Power      *float64 `json:"power"`
		CurrentPos *float64 `json:"current_pos"`
	} `json:"rollers"`
	Tmp *struct {
		TC      *float64 `json:"tC"`
		IsValid *bool    `json:"is_valid"`
	} `json:"tmp"`
	Temperature *float64 `json:"temperature"`
	Hum         *struct {
		Value *float64 `json:"value"`
	} `json:"hum"`
	Lux *struct {
		Value *float64 `json:"value"`
	} `json:"lux"`
	Flood  *bool `json:"flood"`
	Smoke  *bool `json:"smoke"`
	Sensor *struct {
		State string `json:"state"`
	} `json:"sensor"`
	Bat *struct {
		Value   *float64 `json:"value"`
		Voltage *float64 `json:"voltage"`
	} `json:"bat"`
	Cloud *struct {
		Enabled   bool `json:"enabled"`
		Connected bool `json:"connected"`
	} `json:"cloud"`
}

type gen1NamedSettings struct {
	Relays []struct {
		Name *string `json:"name"`
	} `json:"relays"`
	Rollers []struct {
		Name *string `json:"name"`
	} `json:"rollers"`
	Lights []struct {
		Name *string `json:"name"`
	} `json:"lights"`
}

func gen1Detail(statusRaw, settingsRaw json.RawMessage) *Detail {
	var s gen1Raw
	if json.Unmarshal(statusRaw, &s) != nil {
		return nil
	}
	var set gen1NamedSettings
	_ = json.Unmarshal(settingsRaw, &set)
	name := func(list []struct {
		Name *string `json:"name"`
	}, i int) string {
		if i < len(list) && list[i].Name != nil {
			return *list[i].Name
		}
		return ""
	}
	num := func(label string, p *float64, unit string, scale float64) []Value {
		if p == nil {
			return nil
		}
		v := *p
		if scale != 0 {
			v = round(v*scale, 3)
		}
		return []Value{{label, v, unit}}
	}

	d := &Detail{At: time.Now()}
	for i, r := range s.Relays {
		on := r.IsOn
		c := Component{Kind: "switch", ID: i, Name: name(set.Relays, i), On: &on}
		if i < len(s.Meters) && len(s.EMeters) == 0 {
			m := s.Meters[i]
			c.Values = append(c.Values, num("Leistung", m.Power, "W", 0)...)
			c.Values = append(c.Values, num("Energie gesamt", m.Total, "kWh", 1.0/60000)...)
		}
		if r.Overpower {
			c.Values = append(c.Values, Value{"Überlast", true, ""})
		}
		d.Components = append(d.Components, c)
	}
	for i, l := range s.Lights {
		on := l.IsOn
		c := Component{Kind: "light", ID: i, Name: name(set.Lights, i), On: &on}
		c.Values = append(c.Values, num("Helligkeit", l.Brightness, "%", 0)...)
		c.Values = append(c.Values, num("Leistung", l.Power, "W", 0)...)
		if l.Mode != "" {
			c.Values = append(c.Values, Value{"Modus", l.Mode, ""})
		}
		d.Components = append(d.Components, c)
	}
	for i, r := range s.Rollers {
		c := Component{Kind: "cover", ID: i, Name: name(set.Rollers, i), State: r.State}
		c.Values = append(c.Values, num("Position", r.CurrentPos, "%", 0)...)
		c.Values = append(c.Values, num("Leistung", r.Power, "W", 0)...)
		d.Components = append(d.Components, c)
	}
	// Leistungsmesser ohne Relais (z.B. Shelly EM hat emeters, Plug hat meters+relay)
	if len(s.Relays) == 0 {
		for i, m := range s.Meters {
			c := Component{Kind: "pm1", ID: i}
			c.Values = append(c.Values, num("Leistung", m.Power, "W", 0)...)
			c.Values = append(c.Values, num("Energie gesamt", m.Total, "kWh", 1.0/60000)...)
			d.Components = append(d.Components, c)
		}
	}
	for i, e := range s.EMeters {
		c := Component{Kind: "em1", ID: i}
		c.Values = append(c.Values, num("Leistung", e.Power, "W", 0)...)
		c.Values = append(c.Values, num("Spannung", e.Voltage, "V", 0)...)
		c.Values = append(c.Values, num("Strom", e.Current, "A", 0)...)
		c.Values = append(c.Values, num("Leistungsfaktor", e.PF, "", 0)...)
		c.Values = append(c.Values, num("Energie gesamt", e.Total, "kWh", 0.001)...)
		c.Values = append(c.Values, num("Einspeisung gesamt", e.TotalRe, "kWh", 0.001)...)
		d.Components = append(d.Components, c)
	}
	for i, in := range s.Inputs {
		on := in.Input == 1
		c := Component{Kind: "input", ID: i, On: &on}
		if in.Event != "" {
			c.Values = append(c.Values, Value{"Letztes Ereignis", in.Event, ""})
		}
		d.Components = append(d.Components, c)
	}

	sensor := Component{Kind: "sensor"}
	if s.Tmp != nil && (s.Tmp.IsValid == nil || *s.Tmp.IsValid) {
		sensor.Values = append(sensor.Values, num("Temperatur", s.Tmp.TC, "°C", 0)...)
	} else if s.Temperature != nil {
		sensor.Values = append(sensor.Values, num("Gerätetemperatur", s.Temperature, "°C", 0)...)
	}
	if s.Hum != nil {
		sensor.Values = append(sensor.Values, num("Luftfeuchte", s.Hum.Value, "%", 0)...)
	}
	if s.Lux != nil {
		sensor.Values = append(sensor.Values, num("Helligkeit", s.Lux.Value, "lx", 0)...)
	}
	if s.Sensor != nil && s.Sensor.State != "" {
		sensor.State = s.Sensor.State
		sensor.Values = append(sensor.Values, Value{"Kontakt", s.Sensor.State, ""})
	}
	if s.Flood != nil {
		sensor.Values = append(sensor.Values, Value{"Wasser erkannt", *s.Flood, ""})
	}
	if s.Smoke != nil {
		sensor.Values = append(sensor.Values, Value{"Rauch erkannt", *s.Smoke, ""})
	}
	if s.Bat != nil {
		sensor.Values = append(sensor.Values, num("Batterie", s.Bat.Value, "%", 0)...)
		sensor.Values = append(sensor.Values, num("Batteriespannung", s.Bat.Voltage, "V", 0)...)
	}
	if len(sensor.Values) > 0 {
		d.Components = append(d.Components, sensor)
	}
	if s.Cloud != nil {
		on, conn := s.Cloud.Enabled, s.Cloud.Connected
		d.CloudOn, d.CloudConn = &on, &conn
	}
	return d
}

// mergeDetail übernimmt aus dem alten Stand, was ein Poll nicht liefert
// (Kanalnamen und Cloud-Server kommen nur mit der Konfiguration).
func mergeDetail(old, nu *Detail) {
	if old == nil || nu == nil {
		return
	}
	names := map[string]string{}
	for _, c := range old.Components {
		if c.Name != "" {
			names[c.Kind+":"+strconv.Itoa(c.ID)] = c.Name
		}
	}
	for i := range nu.Components {
		c := &nu.Components[i]
		if c.Name == "" {
			c.Name = names[c.Kind+":"+strconv.Itoa(c.ID)]
		}
	}
	if nu.CloudSrv == "" {
		nu.CloudSrv = old.CloudSrv
	}
	if nu.CloudOn == nil {
		nu.CloudOn = old.CloudOn
	}
}

func applyNames(d *Detail, names map[string]string) {
	for i := range d.Components {
		c := &d.Components[i]
		if n := names[c.Kind+":"+strconv.Itoa(c.ID)]; n != "" {
			c.Name = n
		}
	}
}
