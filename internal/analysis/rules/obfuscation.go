package rules

import (
	"math"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/phalanx-security/phalanx/internal/analysis"
)

type ObfuscationRule struct{}

func (r *ObfuscationRule) ID() string {
	return "JS-OBFUSCATION"
}

func (r *ObfuscationRule) Name() string {
	return "Code Obfuscation & Dynamic Eval"
}

func (r *ObfuscationRule) Description() string {
	return "Detects usage of eval(), high entropy strings, or dynamically constructed functions."
}

func shannonEntropy(s string) float64 {
	counts := make(map[rune]float64)
	for _, char := range s {
		counts[char]++
	}

	entropy := 0.0
	length := float64(len(s))
	for _, count := range counts {
		freq := count / length
		entropy -= freq * math.Log2(freq)
	}
	return entropy
}

func (r *ObfuscationRule) Analyze(node interface{}, report func(analysis.Finding)) {
	Walk(node, func(n interface{}) bool {
		switch expr := n.(type) {
		case *ast.CallExpression:
			if ident, ok := expr.Callee.(*ast.Identifier); ok {
				if string(ident.Name) == "eval" {
					report(analysis.Finding{
						RuleID:      r.ID(),
						Severity:    "HIGH",
						Line:        int(ident.Idx),
						Description: "Usage of eval() is highly suspicious in dependency trees.",
					})
				}
				if string(ident.Name) == "Function" {
					report(analysis.Finding{
						RuleID:      r.ID(),
						Severity:    "HIGH",
						Line:        int(ident.Idx),
						Description: "Usage of Function constructor points to dynamically constructed payloads.",
					})
				}
			}
		case *ast.NewExpression:
			if ident, ok := expr.Callee.(*ast.Identifier); ok {
				if string(ident.Name) == "Function" {
					report(analysis.Finding{
						RuleID:      r.ID(),
						Severity:    "HIGH",
						Line:        int(ident.Idx),
						Description: "Usage of new Function() dynamically constructs payloads.",
					})
				}
			}
		case *ast.StringLiteral:
			// Heuristic: If a string is very long and has high entropy, it might be an encrypted payload.
			strVal := string(expr.Value)
			if len(strVal) > 500 {
				ent := shannonEntropy(strVal)
				// Typical english text or normal code has entropy ~4.0-5.0. Base64 is ~6.0. Encrypted is ~7.0+
				if ent > 6.0 {
					report(analysis.Finding{
						RuleID:      "JS-ENTROPY",
						Severity:    "MEDIUM",
						Line:        int(expr.Idx0()),
						Description: "String literal has unusually high entropy (potential base64/encrypted payload).",
					})
				}

				// Just detecting base64 keywords is weak, but looking for massive hex or base64 blobs is common.
				if strings.Contains(strVal, "data:text/javascript;base64,") {
					report(analysis.Finding{
						RuleID:      r.ID(),
						Severity:    "HIGH",
						Line:        int(expr.Idx0()),
						Description: "Found embedded base64 payload.",
					})
				}
			}
		}
		return true
	})
}
