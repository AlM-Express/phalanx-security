package rules

import (
	"github.com/dop251/goja/ast"
	"github.com/phalanx-security/phalanx/internal/analysis"
)

type ChildProcessRule struct{}

func (r *ChildProcessRule) ID() string {
	return "JS-CHILD-PROCESS"
}

func (r *ChildProcessRule) Name() string {
	return "Child Process Execution"
}

func (r *ChildProcessRule) Description() string {
	return "Detects execution of child_process commands like exec or spawn"
}

func (r *ChildProcessRule) Analyze(node interface{}, report func(analysis.Finding)) {
	Walk(node, func(n interface{}) bool {
		callExpr, ok := n.(*ast.CallExpression)
		if !ok {
			return true
		}

		// Simple heuristic: look for object property access 'exec', 'spawn', 'execSync'
		if dotToken, ok := callExpr.Callee.(*ast.DotExpression); ok {
			propName := string(dotToken.Identifier.Name)
			if propName == "exec" || propName == "spawn" || propName == "execSync" || propName == "spawnSync" {
				report(analysis.Finding{
					RuleID:      r.ID(),
					Severity:    "HIGH",
					Line:        int(dotToken.Idx0()),
					Description: "Usage of " + propName + " which executes external commands",
				})
			}
		}

		// Check for direct calls to cp.exec if cp was required (basic check)
		if ident, ok := callExpr.Callee.(*ast.Identifier); ok {
			if string(ident.Name) == "exec" || string(ident.Name) == "spawn" {
				report(analysis.Finding{
					RuleID:      r.ID(),
					Severity:    "HIGH",
					Line:        int(ident.Idx),
					Description: "Direct usage of " + string(ident.Name) + " which may execute external commands",
				})
			}
		}
		return true
	})
}
