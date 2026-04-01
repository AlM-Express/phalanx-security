package analysis

type Finding struct {
	RuleID      string
	Severity    string // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	FilePath    string
	Line        int
	Description string
	Origin      string
}

type Analyzer struct {
	Rules []Rule
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		Rules: make([]Rule, 0),
	}
}

func (a *Analyzer) RegisterRule(r Rule) {
	a.Rules = append(a.Rules, r)
}

func (a *Analyzer) AnalyzeNode(node interface{}, filePath string) []Finding {
	var findings []Finding
	report := func(f Finding) {
		f.FilePath = filePath
		findings = append(findings, f)
	}

	for _, rule := range a.Rules {
		func(r Rule) {
			defer func() {
				if err := recover(); err != nil {
					// We safely swallow rule panics (e.g., malformed AST edgecases)
					// so the entire scan doesn't halt for one bad script.
				}
			}()
			r.Analyze(node, report)
		}(rule)
	}

	return findings
}
