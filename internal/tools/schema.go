package tools

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/google/jsonschema-go/jsonschema"
	"golang.org/x/exp/constraints"
)

// jsonschemaForExt builds a JSON Schema for T using the base generator
// and enriches it with descriptions from `mcp` struct tags and defaults
// from `default` struct tags.
func jsonschemaForExt[T any]() *jsonschema.Schema {
	sch, err := jsonschema.For[T](nil)
	if err != nil {
		panic(err)
	}

	var zero T
	t := reflect.TypeOf(zero)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		panic("bad type")
	}

	if sch.Properties == nil {
		sch.Properties = make(map[string]*jsonschema.Schema)
	}

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		jsonTag := f.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}
		name := jsonTag
		if name == "" {
			name = f.Name
		}
		if comma := strings.IndexByte(name, ','); comma >= 0 {
			name = name[:comma]
		}
		if name == "" {
			name = f.Name
		}

		p, ok := sch.Properties[name]
		if !ok || p == nil {
			// Ensure a schema exists so we can annotate it
			p = &jsonschema.Schema{}
			sch.Properties[name] = p
		}

		if def := f.Tag.Get("default"); def != "" {
			typ := f.Type
			if typ.Kind() == reflect.Ptr {
				typ = typ.Elem()
			}
			switch reflect.Zero(typ).Interface().(type) {
			case int:
				p.Default = parseSigned[int](def)
			case int8:
				p.Default = parseSigned[int8](def)
			case int16:
				p.Default = parseSigned[int16](def)
			case int32:
				p.Default = parseSigned[int32](def)
			case int64:
				p.Default = parseSigned[int64](def)
			case uint:
				p.Default = parseUnsigned[uint](def)
			case uintptr:
				p.Default = parseUnsigned[uintptr](def)
			case uint8:
				p.Default = parseUnsigned[uint8](def)
			case uint16:
				p.Default = parseUnsigned[uint16](def)
			case uint32:
				p.Default = parseUnsigned[uint32](def)
			case uint64:
				p.Default = parseUnsigned[uint64](def)
			case float32:
				p.Default = parseFloat[float32](def)
			case float64:
				p.Default = parseFloat[float64](def)
			case string:
				bs, err := json.Marshal(def)
				if err != nil {
					panic(err) // unreachable
				}
				p.Default = json.RawMessage(bs)
			default:
				panic(fmt.Errorf("unsupported type %s for default value", f.Type))
			}
		}
	}

	return sch
}

func parseSigned[T constraints.Signed](x string) json.RawMessage {
	v, err := strconv.ParseInt(x, 10, int(unsafe.Sizeof(T(0))*8))
	if err != nil {
		panic(fmt.Errorf("failed to parse %s as %T: %w", x, T(0), err))
	}
	n := T(v)
	bs, err := json.Marshal(n)
	if err != nil {
		panic(err) // unreachable
	}
	return json.RawMessage(bs)
}

func parseUnsigned[T constraints.Unsigned](x string) json.RawMessage {
	v, err := strconv.ParseUint(x, 10, int(unsafe.Sizeof(T(0))*8))
	if err != nil {
		panic(fmt.Errorf("failed to parse %s as %T: %w", x, T(0), err))
	}
	n := T(v)
	bs, err := json.Marshal(n)
	if err != nil {
		panic(err) // unreachable
	}
	return json.RawMessage(bs)
}

func parseFloat[T constraints.Float](x string) json.RawMessage {
	v, err := strconv.ParseFloat(x, int(unsafe.Sizeof(T(0))*8))
	if err != nil {
		panic(fmt.Errorf("failed to parse %s as %T: %w", x, T(0), err))
	}
	n := T(v)
	bs, err := json.Marshal(n)
	if err != nil {
		panic(err) // unreachable
	}
	return json.RawMessage(bs)
}
