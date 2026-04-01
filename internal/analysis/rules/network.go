package rules

import (
	"github.com/dop251/goja/ast"
	"github.com/phalanx-security/phalanx/internal/analysis"
	"github.com/phalanx-security/phalanx/internal/ioc"
)

type NetworkRule struct{}

func (r *NetworkRule) ID() string {
	return "JS-NETWORK-ACCESS"
}

func (r *NetworkRule) Name() string {
	return "Network Access"
}

func (r *NetworkRule) Description() string {
	return "Detects usage of network modules like http, net, or fetch, and cross-references against IOC list."
}

func (r *NetworkRule) Analyze(node interface{}, report func(analysis.Finding)) {
	Walk(node, func(n interface{}) bool {
		switch callExpr := n.(type) {
		case *ast.CallExpression:
			if ident, ok := callExpr.Callee.(*ast.Identifier); ok {
				if string(ident.Name) == "require" && len(callExpr.ArgumentList) > 0 {
					if lit, ok := callExpr.ArgumentList[0].(*ast.StringLiteral); ok {
						mod := string(lit.Value)
						if mod == "http" || mod == "https" || mod == "net" ||
							mod == "node:http" || mod == "node:https" || mod == "node:net" {
							report(analysis.Finding{
								RuleID:      r.ID(),
								Severity:    "MEDIUM",
								Line:        int(callExpr.Idx0()),
								Description: "Loading network module: " + mod,
							})
						}
					}
				}
				if string(ident.Name) == "fetch" && len(callExpr.ArgumentList) > 0 {
					severity := "MEDIUM"
					description := "Usage of global fetch API for network requests"

					if lit, ok := callExpr.ArgumentList[0].(*ast.StringLiteral); ok {
						if ioc.CheckDomain(string(lit.Value)) {
							severity = "CRITICAL"
							description = "KNOWN MALICIOUS C2 DETECTED via fetch: " + string(lit.Value)
						}
					}

					report(analysis.Finding{
						RuleID:      r.ID(),
						Severity:    severity,
						Line:        int(callExpr.Idx0()),
						Description: description,
					})
				} else if string(ident.Name) == "fetch" {
					report(analysis.Finding{
						RuleID:      r.ID(),
						Severity:    "MEDIUM",
						Line:        int(callExpr.Idx0()),
						Description: "Usage of global fetch API for network requests",
					})
				}
			}
		}
		return true
	})
}
