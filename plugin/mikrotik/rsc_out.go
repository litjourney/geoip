package mikrotik

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/litjourney/geoip/lib"
)

const (
	typeMikrotikScriptOut = "mikrotikGeoIPScript"
	descMikrotikScriptOut = "Convert data to mikrotik script format"
	defaultACListName     = "CN"
)

var (
	defaultOutputName = "mikrotik-acl.rsc"
	defaultOutputDir  = filepath.Join("./", "output", "mikrotik")
)

func init() {
	lib.RegisterOutputConfigCreator(typeMikrotikScriptOut, func(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
		return newMikrotikScript(action, data)
	})
	lib.RegisterOutputConverter(typeMikrotikScriptOut, &mikrotikScriptOut{
		Description: descMikrotikScriptOut,
	})
}

type mikrotikScriptOut struct {
	Type        string
	Action      lib.Action
	Description string
	OutputName  string
	OutputDir   string
	Want        []string
	Overwrite   []string
	ACListName  string
	OnlyIPType  lib.IPType
}

func newMikrotikScript(action lib.Action, data json.RawMessage) (lib.OutputConverter, error) {
	var tmp struct {
		OutputName string     `json:"outputName"`
		OutputDir  string     `json:"outputDir"`
		Want       []string   `json:"wantedList"`
		OnlyIPType lib.IPType `json:"onlyIPType"`
		ACListName string     `json:"aclistName"`
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, err
		}
	}

	if tmp.OutputName == "" {
		tmp.OutputName = defaultOutputName
	}

	if tmp.OutputDir == "" {
		tmp.OutputDir = defaultOutputDir
	}

	if tmp.ACListName == "" {
		tmp.ACListName = defaultACListName
	}

	return &mikrotikScriptOut{
		Type:        typeMikrotikScriptOut,
		Action:      action,
		Description: descMikrotikScriptOut,
		OutputName:  tmp.OutputName,
		OutputDir:   tmp.OutputDir,
		Want:        tmp.Want,
		OnlyIPType:  tmp.OnlyIPType,
		ACListName:  tmp.ACListName,
	}, nil
}

func (o *mikrotikScriptOut) GetType() string {
	return o.Type
}

func (o *mikrotikScriptOut) GetAction() lib.Action {
	return o.Action
}

func (o *mikrotikScriptOut) GetDescription() string {
	return o.Description
}

func (o *mikrotikScriptOut) Output(container lib.Container) error {

	updated := false

	var data []byte

	data = append(data, o.addMikrotikScriptPrefix()...)

	for _, name := range o.getEntryNameListInOrder(container) {
		entry, found := container.GetEntry(name)
		if !found {
			log.Printf("❌ entry %s not found", name)
			continue
		}
		d, err := o.marshalData(entry)
		if err != nil {
			return err
		}
		data = append(data, d...)
		updated = true
	}
	filename := strings.ToLower(o.OutputName)
	if err := o.writeFile(filename, data); err != nil {
		return err
	}
	updated = true
	if updated {
		if err := o.writeFile(o.OutputName, data); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("type %s | action %s failed to write file", o.Type, o.Action)

	}
	return nil
}

func (o *mikrotikScriptOut) writeFile(filename string, data []byte) error {
	if err := os.MkdirAll(o.OutputDir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(o.OutputDir, filename), data, 0644); err != nil {
		return err
	}
	log.Printf("✅ [%s] %s --> %s", o.Type, filename, o.OutputDir)
	return nil
}

func (o *mikrotikScriptOut) marshalData(entry *lib.Entry) ([]byte, error) {
	var err error

	var entryCidr []string
	switch o.OnlyIPType {
	case lib.IPv4:
		entryCidr, err = entry.MarshalText(lib.IgnoreIPv6)
	case lib.IPv6:
		entryCidr, err = entry.MarshalText(lib.IgnoreIPv4)
	default:
		entryCidr, err = entry.MarshalText()
	}
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	for _, cidr := range entryCidr {
		buf.WriteString(fmt.Sprintf(":do { add address=%s list=%s } on-error={}\n", cidr, o.ACListName))
	}

	return buf.Bytes(), nil
}

func (o *mikrotikScriptOut) addMikrotikScriptPrefix() []byte {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("/log info \"Loading %s address list\"", o.ACListName))
	buf.WriteString(fmt.Sprintf("/ip firewall address-list remove [/ip firewall address-list find list=%s]\n", o.ACListName))
	buf.WriteString("/ip firewall address-list\n")
	return buf.Bytes()
}

func (o *mikrotikScriptOut) getEntryNameListInOrder(container lib.Container) []string {
	wantList := make([]string, 0, 200)
	for _, want := range o.Want {
		if want = strings.ToUpper(strings.TrimSpace(want)); want != "" {
			wantList = append(wantList, want)
		}
	}
	if len(wantList) > 0 {
		return wantList
	}
	overwirteList := make([]string, 0, 200)
	overwirteMap := make(map[string]bool)
	for _, overwrite := range o.Overwrite {
		if overwrite = strings.ToUpper(strings.TrimSpace(overwrite)); overwrite != "" {
			overwirteList = append(overwirteList, overwrite)
			overwirteMap[overwrite] = true
		}
	}
	list := make([]string, 0, 200)
	for entry := range container.Loop() {
		name := entry.GetName()
		_, found := overwirteMap[name]
		if found {
			continue
		}
		list = append(list, name)
	}
	list = append(list, overwirteList...)
	return list

}
