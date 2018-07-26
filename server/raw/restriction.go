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
		if strings.HasPrefix(n, x) {
			return true
		}
	}
	return false
}

func hasAnySuffix(a []string, x string) bool {
	for _, n := range a {
		if strings.HasPrefix(n, x) {
			return true
		}
	}
	return false
}

func separateRestrictions() ([]string, []string, []string) {
	return strings.Split(*allowOnlyPrefix, ","), strings.Split(*allowOnlySuffix, ","), strings.Split(*allowOnly, ",")
}

func commandLineRestrictor(from string) bool {
	if *allowOnlyPrefix == "" && *allowOnlySuffix == "" && *allowOnly == "" {
		return false
	}

	px, sx, o := separateRestrictions()

	return !(hasAnyPrefix(px, from) || hasAnySuffix(sx, from) || contains(o, from))
}
