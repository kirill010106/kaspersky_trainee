package domain

import (
	"strings"
	"unicode/utf8"
)

// NormalizeAndValidate trims Name and validates editable threat metadata.
// It leaves Description unchanged and does not modify the receiver.
func (data ThreatData) NormalizeAndValidate() (ThreatData, error) {
	if !utf8.ValidString(data.Name) || strings.ContainsRune(data.Name, 0) {
		return ThreatData{}, &ValidationError{
			Field:   "name",
			Message: "must be valid UTF-8 without NUL characters",
		}
	}

	data.Name = strings.TrimSpace(data.Name)

	if length := utf8.RuneCountInString(data.Name); length < 1 || length > 200 {
		return ThreatData{}, &ValidationError{
			Field:   "name",
			Message: "must contain 1 to 200 Unicode code points after trimming",
		}
	}

	if !utf8.ValidString(data.Description) ||
		strings.ContainsRune(data.Description, 0) {
		return ThreatData{}, &ValidationError{
			Field:   "description",
			Message: "must be valid UTF-8 without NUL characters",
		}
	}

	if utf8.RuneCountInString(data.Description) > 4096 {
		return ThreatData{}, &ValidationError{
			Field:   "description",
			Message: "must contain at most 4096 Unicode code points",
		}
	}

	switch data.Type {
	case ThreatTypeTrojan, ThreatTypeRansomware, ThreatTypeSpyware,
		ThreatTypeAdware, ThreatTypeWorm, ThreatTypeOther:
	default:
		return ThreatData{}, &ValidationError{
			Field:   "type",
			Message: "must be a supported threat type",
		}
	}

	switch data.Severity {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
	default:
		return ThreatData{}, &ValidationError{
			Field:   "severity",
			Message: "must be a supported severity level",
		}
	}

	return data, nil
}
