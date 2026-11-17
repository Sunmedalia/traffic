package main

import (
	"regexp/syntax"
	"strings"
)

// Each branch is a conjunction of necessary substrings; a match implies
// all substrings in at least one branch are present. An optional/unknown alternative disables filtering.
// Non-ASCII input always uses RE2, preserving Unicode folding (e.g. K/K).
func necessaryRuleLiterals(expression *syntax.Regexp) [][]string {
	switch expression.Op {
	case syntax.OpLiteral:
		if len(expression.Rune) == 0 {
			return nil
		}
		for _, r := range expression.Rune {
			if r > 127 {
				return nil
			}
		}
		return [][]string{{strings.ToLower(string(expression.Rune))}}
	case syntax.OpCharClass:
		var alternatives [][]string
		for i := 0; i < len(expression.Rune); i += 2 {
			low, high := expression.Rune[i], expression.Rune[i+1]
			if high > 127 || len(alternatives)+int(high-low)+1 > 16 {
				return nil
			}
			for value := low; value <= high; value++ {
				alternatives = append(alternatives, []string{strings.ToLower(string(value))})
			}
		}
		return alternatives
	case syntax.OpCapture, syntax.OpPlus:
		return necessaryRuleLiterals(expression.Sub[0])
	case syntax.OpRepeat:
		if expression.Min > 0 {
			return necessaryRuleLiterals(expression.Sub[0])
		}
	case syntax.OpConcat:
		var conjunctions [][]string
		for _, child := range expression.Sub {
			candidate := necessaryRuleLiterals(child)
			if len(candidate) == 0 {
				continue
			}
			if len(conjunctions) == 0 {
				conjunctions = candidate
				continue
			}
			// Retaining only some necessary conditions is conservative when a
			// pathological custom expression would expand the DNF beyond its bound.
			if len(conjunctions)*len(candidate) > 32 {
				continue
			}
			var combined [][]string
			for _, left := range conjunctions {
				for _, right := range candidate {
					if len(left)+len(right) > 32 {
						combined = append(combined, left)
						continue
					}
					row := append([]string(nil), left...)
					row = append(row, right...)
					combined = append(combined, row)
				}
			}
			conjunctions = combined
		}
		return conjunctions
	case syntax.OpAlternate:
		var alternatives [][]string
		for _, child := range expression.Sub {
			candidate := necessaryRuleLiterals(child)
			if len(candidate) == 0 || len(alternatives)+len(candidate) > 32 {
				return nil
			}
			alternatives = append(alternatives, candidate...)
		}
		return alternatives
	}
	return nil
}
func foldedASCII(text string) (string, bool) {
	for i := range text {
		if text[i] >= 128 {
			return "", false
		}
	}
	return strings.ToLower(text), true
}
func (r Rule) mayMatch(view decodedView) bool {
	if len(r.requiredLiterals) == 0 || !view.ascii {
		return true
	}
	for _, branch := range r.requiredLiterals {
		possible := true
		for _, literal := range branch {
			if !strings.Contains(view.folded, literal) {
				possible = false
				break
			}
		}
		if possible {
			return true
		}
	}
	return false
}
