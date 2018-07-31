package main

import "strings"

func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func hasAnyPrefix(a []string, x string) bool {
	for _, n := range a {
		if strings.HasPrefix(x, n) {
			return true
		}
	}
	return false
}

func hasAnySuffix(a []string, x string) bool {
	for _, n := range a {
		if strings.HasSuffix(x, n) {
			return true
		}
	}
	return false
}

func splitOrEmpty(s, sep string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, sep)
}

func separateRestrictions() ([]string, []string, []string) {
	return splitOrEmpty(*allowOnlyPrefix, ","), splitOrEmpty(*allowOnlySuffix, ","), splitOrEmpty(*allowOnly, ",")
}

func commandLineRestrictor(from string) bool {
	if *allowOnlyPrefix == "" && *allowOnlySuffix == "" && *allowOnly == "" {
		return false
	}

	px, sx, o := separateRestrictions()

	return !(hasAnyPrefix(px, from) || hasAnySuffix(sx, from) || contains(o, from))
}
