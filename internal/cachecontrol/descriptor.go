package cachecontrol

// Descriptor is the immutable capability advertisement for a registered type.
// Secret-free: no paths with credentials, no subjects, no tokens.
type Descriptor struct {
	TypeID             TypeID         `json:"typeId"`
	DisplayName        string         `json:"displayName"`
	StorageClass       StorageClass   `json:"storageClass"`
	Implementation     string         `json:"implementation"`
	Availability       Availability   `json:"availability"`
	AvailabilityReason string         `json:"availabilityReason,omitempty"`
	SchemaVersion      int            `json:"schemaVersion"`
	SupportedModes     []Mode         `json:"supportedModes"`
	DynamicFields      []string       `json:"dynamicFields,omitempty"`
	StartupOnlyFields  []string       `json:"startupOnlyFields,omitempty"`
	SelectorFields     []string       `json:"selectorFields,omitempty"`
	SupportsList       bool           `json:"supportsList"`
	SupportsDumpModes  []DumpMode     `json:"supportsDumpModes,omitempty"`
	SupportsPurge      bool           `json:"supportsPurge"`
	SupportsVerify     bool           `json:"supportsVerify"`
	SupportsRepair     bool           `json:"supportsRepair"`
	SupportsGC         bool           `json:"supportsGC"`
	SupportsPinning    bool           `json:"supportsPinning"`
	SupportsRangeRead  bool           `json:"supportsRangeRead"`
	SupportsFleetShare bool           `json:"supportsFleetShare"`
	SizeAccounting     SizeAccounting `json:"sizeAccounting"`
}

// SupportsMode reports whether the descriptor allows m.
func (d Descriptor) SupportsMode(m Mode) bool {
	for _, sm := range d.SupportedModes {
		if sm == m {
			return true
		}
	}
	return false
}

// SupportsDump reports whether the descriptor allows dump mode d.
func (d Descriptor) SupportsDump(mode DumpMode) bool {
	for _, sm := range d.SupportsDumpModes {
		if sm == mode {
			return true
		}
	}
	return false
}

// EnablementAllowed is false when the type cannot leave off (unqualified/unavailable).
func (d Descriptor) EnablementAllowed() bool {
	switch d.Availability {
	case AvailabilityAvailable, AvailabilityDegraded:
		return true
	default:
		return false
	}
}
