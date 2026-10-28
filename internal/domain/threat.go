package domain

import (
	"strings"
	"time"
)

type ThreatType string

const (
	ThreatTypeTrojan     ThreatType = "trojan"
	ThreatTypeRansomware ThreatType = "ransomware"
	ThreatTypeSpyware    ThreatType = "spyware"
	ThreatTypeAdware     ThreatType = "adware"
	ThreatTypeWorm       ThreatType = "worm"
	ThreatTypeOther      ThreatType = "other"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ThreatData holds editable metadata; MD5 and timestamps are managed separately.
type ThreatData struct {
	Name        string
	Description string
	Type        ThreatType
	Severity    Severity
}

// Threat is a stored record with its canonical MD5 and database timestamps.
type Threat struct {
	MD5         string
	Name        string
	Description string
	Type        ThreatType
	Severity    Severity
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Field + ": " + e.Message
}

// NormalizeMD5 validates exactly 32 ASCII hexadecimal characters
// and returns their lowercase representation.
func NormalizeMD5(value string) (string, error) {
	if len(value) != 32 {
		return "", &ValidationError{
			Field:   "md5",
			Message: "must contain exactly 32 ASCII hexadecimal characters",
		}
	}

	for _, c := range value {
		if !((c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'f') ||
			(c >= 'A' && c <= 'F')) {
			return "", &ValidationError{
				Field:   "md5",
				Message: "must contain only ASCII hexadecimal characters",
			}
		}
	}

	return strings.ToLower(value), nil
}
