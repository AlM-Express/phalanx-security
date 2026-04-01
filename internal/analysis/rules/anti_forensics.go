package rules

import (
	"github.com/dop251/goja/ast"
	"github.com/phalanx-security/phalanx/internal/analysis"
)

type AntiForensicsRule struct{}

func (r *AntiForensicsRule) ID() string {
	return "JS-ANTI-FORENSICS"
}

func (r *AntiForensicsRule) Name() string {
	return "Anti-Forensics & Log Clearing"
}

func (r *AntiForensicsRule) Description() string {
	return "Detects routines attempting to delete files (fs.unlink) especially self-referential like __filename"
}

func (r *AntiForensicsRule) Analyze(node interface{}, report func(analysis.Finding)) {
	Walk(node, func(n interface{}) bool {
		switch callExpr := n.(type) {
		case *ast.CallExpression:
			if dotToken, ok := callExpr.Callee.(*ast.DotExpression); ok {
				propName := string(dotToken.Identifier.Name)
				if propName == "unlink" || propName == "unlinkSync" || propName == "rmSync" {
					// Detect if they are unlinking __filename to hide tracks
					for _, arg := range callExpr.ArgumentList {
						if ident, ok := arg.(*ast.Identifier); ok {
							if string(ident.Name) == "__filename" || string(ident.Name) == "__dirname" {
								report(analysis.Finding{
									RuleID:      r.ID(),
									Severity:    "CRITICAL",
									Line:        int(dotToken.Idx0()),
									Description: "Script is attempting to violently delete itself to hide forensic evidence.",
								})
							}
						}
					}
					// Still report generic deletion as medium
					report(analysis.Finding{
						RuleID:      "JS-FS-DELETE",
						Severity:    "MEDIUM",
						Line:        int(dotToken.Idx0()),
						Description: "Usage of " + propName + " to delete files.",
					})
				}
			}
		}
		return true
	})
}
