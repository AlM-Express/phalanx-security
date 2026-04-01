package rules

import (
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/phalanx-security/phalanx/internal/analysis"
)

type FSRule struct{}

func (r *FSRule) ID() string {
	return "JS-FS-ACCESS"
}

func (r *FSRule) Name() string {
	return "Sensitive File System Access"
}

func (r *FSRule) Description() string {
	return "Detects reads to sensitive filesystem locations like /etc/passwd or SSH keys"
}

func (r *FSRule) Analyze(node interface{}, report func(analysis.Finding)) {
	Walk(node, func(n interface{}) bool {
		switch callExpr := n.(type) {
		case *ast.CallExpression:
			// Check if we are passing a string literal that looks like a sensitive file path
			for _, arg := range callExpr.ArgumentList {
				if lit, ok := arg.(*ast.StringLiteral); ok {
					val := strings.ToLower(string(lit.Value))
					if strings.Contains(val, "/etc/passwd") ||
						strings.Contains(val, "/etc/shadow") ||
						strings.Contains(val, "/.ssh/") ||
						strings.Contains(val, "id_rsa") ||
						strings.Contains(val, "/.aws/credentials") ||
						strings.Contains(val, ".bash_history") {
						report(analysis.Finding{
							RuleID:      r.ID(),
							Severity:    "CRITICAL",
							Line:        int(lit.Idx0()),
							Description: "Code attempts to reference a highly sensitive file path: " + string(lit.Value),
						})
					}
				}
			}
		}
		return true
	})
}
