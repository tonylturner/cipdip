package app

import (
	"strconv"
	"strings"

	"github.com/tonylturner/cipdip/internal/cip/spec"
)

func ResolveServiceAlias(value string) string {
	if code, ok := ParseServiceValue(value); ok {
		if alias, ok := spec.ServiceAliasName(code); ok {
			return strings.ToLower(alias)
		}
	}
	return ""
}

func ResolveClassAlias(value string) string {
	if code, ok := ParseClassValue(value); ok {
		if alias, ok := spec.ClassAliasName(code); ok {
			return strings.ToLower(alias)
		}
	}
	return ""
}

func ParseServiceValue(value string) (uint8, bool) {
	if code, err := strconv.ParseUint(strings.TrimSpace(value), 0, 8); err == nil {
		return uint8(code), true
	}
	if code, ok := spec.ParseServiceAlias(value); ok {
		return code, true
	}
	return 0, false
}

func ParseClassValue(value string) (uint16, bool) {
	if code, err := strconv.ParseUint(strings.TrimSpace(value), 0, 16); err == nil {
		return uint16(code), true
	}
	if code, ok := spec.ParseClassAlias(value); ok {
		return code, true
	}
	return 0, false
}

func ServiceAliasName(code uint8) (string, bool) {
	return spec.ServiceAliasName(code)
}

func ClassAliasName(code uint16) (string, bool) {
	return spec.ClassAliasName(code)
}
