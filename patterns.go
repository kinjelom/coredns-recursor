package recursor

import (
	"fmt"
	"sort"
	"strings"
)

// aliasPattern is an alias with one `*` inside its name, e.g. `*-x`, `web-*`, `api-*.eu`.
// The `*` matches one or more characters within a single label (no dots), like a TLS
// certificate wildcard, so `*-x` matches `foo-x` but not `-x` or `a.foo-x`.
type aliasPattern struct {
	name   string
	prefix string
	suffix string
}

// isAliasPattern reports whether an alias name is a pattern: it contains `*` but isn't the `*` alias.
func isAliasPattern(name string) bool {
	return name != "*" && strings.Contains(name, "*")
}

// parseAliasPattern splits a pattern name around its single `*`.
func parseAliasPattern(name string) (aliasPattern, error) {
	if strings.Count(name, "*") != 1 {
		return aliasPattern{}, fmt.Errorf("an alias pattern may contain only one '*'")
	}
	prefix, suffix, _ := strings.Cut(name, "*")
	if strings.Contains(name, "..") || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return aliasPattern{}, fmt.Errorf("an alias pattern must not contain empty labels")
	}
	return aliasPattern{name: name, prefix: prefix, suffix: suffix}, nil
}

// match reports whether the pattern matches a query name relative to the zone.
func (p aliasPattern) match(alias string) bool {
	if len(alias) <= len(p.prefix)+len(p.suffix) || !strings.HasPrefix(alias, p.prefix) || !strings.HasSuffix(alias, p.suffix) {
		return false
	}
	return !strings.Contains(alias[len(p.prefix):len(alias)-len(p.suffix)], ".")
}

// sortAliasPatterns orders patterns from the most specific: more literal characters first, then
// a longer suffix (the right side of a DNS name is the more significant one). Two different
// patterns that are equal on both counts can't match the same name, so the order is unambiguous
// and doesn't depend on the order in the configuration; the name only makes the sort stable.
func sortAliasPatterns(patterns []aliasPattern) {
	sort.Slice(patterns, func(i, j int) bool {
		a, b := patterns[i], patterns[j]
		if la, lb := len(a.prefix)+len(a.suffix), len(b.prefix)+len(b.suffix); la != lb {
			return la > lb
		}
		if len(a.suffix) != len(b.suffix) {
			return len(a.suffix) > len(b.suffix)
		}
		return a.name < b.name
	})
}
