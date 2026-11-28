package main

import (
	"regexp/syntax"
	"slices"
	"strings"
)

// A prefilter is a condition every match of a rule implies, tested with
// substring searches on folded text (foldForPrefilter) before the regular
// expression runs. A nil prefilter knows nothing and admits all text. Every
// literal it holds is lowercase ASCII, and folding also maps the only
// non-ASCII runes that case-fold to ASCII letters (ſ, K), so the condition
// holds on UTF-8 and binary text as well as on ASCII.
//
// Substrings are contiguous runs of the expression: `\bor\s+` requires "or"
// followed by a space character, not "or" and a space anywhere. Requests and
// responses contain common short literals, so only such runs reject them.
// Conditions form an AND/OR tree that mirrors the expression, so alternatives
// never multiply into a bounded normal form that has to be discarded.
type prefilter struct {
	text string       // leaf: the substring must occur
	all  []*prefilter // all of these hold
	any  []*prefilter // at least one of these holds
	// strings, set when every alternative of any is a leaf, is searched in
	// one pass: by the shared prefix or suffix, or as a byte set.
	strings *stringSet
}

type stringSet struct {
	values         []string
	prefix, suffix string
	bytes          string // all values are these single bytes
}

func newStringSet(values []string) *stringSet {
	set := &stringSet{values: values, prefix: values[0], suffix: values[0]}
	single := true
	for _, value := range values {
		single = single && len(value) == 1
		for !strings.HasPrefix(value, set.prefix) {
			set.prefix = set.prefix[:len(set.prefix)-1]
		}
		for !strings.HasSuffix(value, set.suffix) {
			set.suffix = set.suffix[1:]
		}
	}
	if single {
		set.bytes = strings.Join(values, "")
	}
	return set
}

func (s *stringSet) occursIn(text string) bool {
	switch {
	case s.bytes != "":
		return strings.ContainsAny(text, s.bytes)
	case s.prefix != "" && len(s.prefix) >= len(s.suffix):
		for at := 0; ; {
			i := strings.Index(text[at:], s.prefix)
			if i < 0 {
				return false
			}
			rest := text[at+i:]
			for _, value := range s.values {
				if strings.HasPrefix(rest, value) {
					return true
				}
			}
			at += i + 1
		}
	case s.suffix != "":
		// Only whether a value occurs matters, so search forward: unlike
		// strings.LastIndex, strings.Index uses the vectorised byte search.
		for at := 0; ; {
			i := strings.Index(text[at:], s.suffix)
			if i < 0 {
				return false
			}
			head := text[:at+i+len(s.suffix)]
			for _, value := range s.values {
				if strings.HasSuffix(head, value) {
					return true
				}
			}
			at += i + 1
		}
	}
	for _, value := range s.values {
		if strings.Contains(text, value) {
			return true
		}
	}
	return false
}

func (p *prefilter) admits(text string) bool {
	switch {
	case p == nil:
		return true
	case p.strings != nil:
		return p.strings.occursIn(text)
	case p.all != nil:
		for _, sub := range p.all {
			if !sub.admits(text) {
				return false
			}
		}
		return true
	case p.any != nil:
		for _, sub := range p.any {
			if sub.admits(text) {
				return true
			}
		}
		return false
	}
	return strings.Contains(text, p.text)
}

// shortest is the length of the shortest text that satisfies p, a rough
// measure of how rarely it holds.
func (p *prefilter) shortest() int {
	switch {
	case p.all != nil:
		longest := 0
		for _, sub := range p.all {
			longest = max(longest, sub.shortest())
		}
		return longest
	case p.any != nil:
		least := -1
		for _, sub := range p.any {
			if n := sub.shortest(); least < 0 || n < least {
				least = n
			}
		}
		return least
	}
	return len(p.text)
}

func allOf(conditions []*prefilter) *prefilter {
	var kept []*prefilter
	for _, condition := range conditions {
		if condition != nil {
			kept = append(kept, condition)
		}
	}
	switch len(kept) {
	case 0:
		return nil
	case 1:
		return kept[0]
	}
	// Test the condition that most rarely holds first; AND stops at the
	// first one that fails.
	slices.SortStableFunc(kept, func(a, b *prefilter) int { return b.shortest() - a.shortest() })
	return &prefilter{all: kept}
}

// anyOfConditions is nil when one alternative is unconstrained.
func anyOfConditions(conditions []*prefilter) *prefilter {
	for _, condition := range conditions {
		if condition == nil {
			return nil
		}
	}
	if len(conditions) == 1 {
		return conditions[0]
	}
	condition := &prefilter{any: conditions}
	values := make([]string, 0, len(conditions))
	for _, sub := range conditions {
		if sub.all != nil || sub.any != nil {
			return condition
		}
		values = append(values, sub.text)
	}
	condition.strings = newStringSet(values)
	return condition
}

// anyOfStrings is the condition "one of these strings occurs".
func anyOfStrings(set []string) *prefilter {
	conditions := make([]*prefilter, 0, len(set))
	for _, value := range set {
		if value == "" {
			// The empty string occurs everywhere: no condition.
			return nil
		}
		conditions = append(conditions, &prefilter{text: value})
	}
	return anyOfConditions(conditions)
}

func rulePrefilter(expression *syntax.Regexp) *prefilter {
	return literalFacts(expression).need
}

// prefilterSetLimit bounds the strings one exact set may hold.
const prefilterSetLimit = 32

// literalFact describes one subexpression. exact, when not nil, lists every
// lowercase ASCII string it can match; need is a condition any match implies.
type literalFact struct {
	exact []string
	need  *prefilter
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := values[:0:0]
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

// concatenate returns every left+right pair, or nil beyond the set bound.
func concatenate(left, right []string) []string {
	if len(left)*len(right) > prefilterSetLimit {
		return nil
	}
	out := make([]string, 0, len(left)*len(right))
	for _, a := range left {
		for _, b := range right {
			out = append(out, a+b)
		}
	}
	return uniqueStrings(out)
}

func literalFacts(expression *syntax.Regexp) literalFact {
	switch expression.Op {
	case syntax.OpLiteral:
		if len(expression.Rune) == 0 {
			return literalFact{}
		}
		for _, r := range expression.Rune {
			if r > 127 {
				return literalFact{}
			}
		}
		value := strings.ToLower(string(expression.Rune))
		return literalFact{exact: []string{value}, need: &prefilter{text: value}}
	case syntax.OpCharClass:
		var set []string
		for i := 0; i < len(expression.Rune); i += 2 {
			low, high := expression.Rune[i], expression.Rune[i+1]
			if high > 127 || len(set)+int(high-low)+1 > 16 {
				return literalFact{}
			}
			for value := low; value <= high; value++ {
				set = append(set, strings.ToLower(string(value)))
			}
		}
		set = uniqueStrings(set)
		return literalFact{exact: set, need: anyOfStrings(set)}
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		// Zero-width: matches only the empty string and keeps neighbours adjacent.
		return literalFact{exact: []string{""}}
	case syntax.OpCapture:
		return literalFacts(expression.Sub[0])
	case syntax.OpQuest:
		inner := literalFacts(expression.Sub[0]).exact
		if inner == nil || len(inner) >= prefilterSetLimit {
			return literalFact{}
		}
		return literalFact{exact: uniqueStrings(append(append([]string(nil), inner...), ""))}
	case syntax.OpPlus:
		return literalFact{need: literalFacts(expression.Sub[0]).need}
	case syntax.OpRepeat:
		if expression.Min > 0 {
			return literalFact{need: literalFacts(expression.Sub[0]).need}
		}
	case syntax.OpConcat:
		return concatFacts(expression.Sub, starExpansions)
	case syntax.OpAlternate:
		var exact []string
		exactKnown := true
		needs := make([]*prefilter, 0, len(expression.Sub))
		for _, child := range expression.Sub {
			fact := literalFacts(child)
			if fact.exact == nil || len(exact)+len(fact.exact) > prefilterSetLimit {
				exactKnown = false
			} else if exactKnown {
				exact = append(exact, fact.exact...)
			}
			needs = append(needs, fact.need)
		}
		fact := literalFact{need: anyOfConditions(needs)}
		if exactKnown {
			fact.exact = uniqueStrings(exact)
		}
		return fact
	}
	return literalFact{}
}

// starExpansions bounds how many x* children of one concatenation are split
// into their empty and repeated cases; each split doubles the work.
const starExpansions = 2

// concatFacts joins adjacent exact children into contiguous runs. A run ends
// at a child without an exact set or when it would outgrow the bound; each
// finished run requires one of its strings. A repeated exact child, such as
// \s+, both ends the run before it and starts the next one. x* is either
// empty, keeping its neighbours adjacent, or x+.
func concatFacts(children []*syntax.Regexp, expansions int) literalFact {
	if expansions > 0 {
		for i, child := range children {
			if child.Op != syntax.OpStar || literalFacts(child.Sub[0]).exact == nil {
				continue
			}
			empty := append(append([]*syntax.Regexp(nil), children[:i]...), children[i+1:]...)
			repeated := append([]*syntax.Regexp(nil), children...)
			repeated[i] = &syntax.Regexp{Op: syntax.OpPlus, Flags: child.Flags, Sub: child.Sub}
			return literalFact{need: anyOfConditions([]*prefilter{
				concatFacts(empty, expansions-1).need,
				concatFacts(repeated, expansions-1).need,
			})}
		}
	}
	var needs []*prefilter
	run := []string{""}
	exact := []string{""}
	finish := func() {
		needs = append(needs, anyOfStrings(run))
		run = []string{""}
	}
	for _, child := range children {
		fact := literalFacts(child)
		if exact != nil && fact.exact != nil {
			exact = concatenate(exact, fact.exact)
		} else {
			exact = nil
		}
		if fact.exact == nil {
			if repeated := repeatedExact(child); repeated != nil {
				// The first repetition follows the run and the last one
				// precedes the next child.
				if joined := concatenate(run, repeated); joined != nil {
					run = joined
				}
				finish()
				run = repeated
				continue
			}
			finish()
			needs = append(needs, fact.need)
			continue
		}
		if joined := concatenate(run, fact.exact); joined != nil {
			run = joined
			continue
		}
		finish()
		run = fact.exact
	}
	finish()
	return literalFact{exact: exact, need: allOf(needs)}
}

// repeatedExact returns the exact set of x in x+ or x{n,m} with n > 0.
func repeatedExact(expression *syntax.Regexp) []string {
	if expression.Op != syntax.OpPlus && (expression.Op != syntax.OpRepeat || expression.Min < 1) {
		return nil
	}
	exact := literalFacts(expression.Sub[0]).exact
	if len(exact) == 0 || (len(exact) == 1 && exact[0] == "") {
		return nil
	}
	return exact
}

// prefilterFold lowercases A-Z and maps every other byte to itself.
var prefilterFold = func() (table [256]byte) {
	for i := range table {
		table[i] = byte(i)
	}
	for c := byte('A'); c <= 'Z'; c++ {
		table[c] = c + 'a' - 'A'
	}
	return table
}()

// foldForPrefilter returns text as prefilters search it: A-Z lowercased, and
// ſ (U+017F) and K (U+212A), the only non-ASCII runes that case-fold to ASCII
// letters, replaced by s and k. Every other byte is kept, and a byte above
// 0x7F equals no literal byte.
//
// RE2 reads text as UTF-8 runes, an invalid byte being one rune. 0xC5 and 0xE2
// are never continuation bytes, so these two sequences always decode as ſ and
// K wherever they occur, and folding maps each rune on its own: the fold of a
// matched substring is a substring of the folded text, with the same order
// and adjacency.
func foldForPrefilter(text string) string {
	i := 0
	for i < len(text) && !mayFold(text[i]) {
		i++
	}
	if i == len(text) {
		return text
	}
	var out strings.Builder
	out.Grow(len(text))
	out.WriteString(text[:i])
	var chunk [4096]byte
	n := 0
	for ; i < len(text); i++ {
		c := text[i]
		switch {
		case c == 0xE2 && i+2 < len(text) && text[i+1] == 0x84 && text[i+2] == 0xAA:
			c, i = 'k', i+2
		case c == 0xC5 && i+1 < len(text) && text[i+1] == 0xBF:
			c, i = 's', i+1
		}
		chunk[n] = prefilterFold[c]
		n++
		if n == len(chunk) {
			out.Write(chunk[:])
			n = 0
		}
	}
	out.Write(chunk[:n])
	return out.String()
}

// mayFold reports whether foldForPrefilter can rewrite a sequence starting at c.
func mayFold(c byte) bool { return c-'A' < 26 || c == 0xC5 || c == 0xE2 }

func (r Rule) mayMatch(view decodedView) bool {
	return r.prefilter.admits(view.folded)
}
