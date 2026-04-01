package scoring

import (
	"fmt"
	"github.com/phalanx-security/phalanx/internal/analysis"
)

type DiffResult struct {
	NewScore        int
	ScoreShift      int
	AddedFindings   []string
	RemovedFindings []string
}

func Compare(oldScore, newScore ScoreResult, oldFindings, newFindings []analysis.Finding) DiffResult {
	shift := newScore.TotalScore - oldScore.TotalScore

	oldRules := make(map[string]bool)
	for _, f := range oldFindings {
		oldRules[f.RuleID+":"+f.FilePath] = true
	}

	newRules := make(map[string]bool)
	var added []string
	for _, f := range newFindings {
		key := f.RuleID + ":" + f.FilePath
		newRules[key] = true
		if !oldRules[key] {
			added = append(added, fmt.Sprintf("[%s] %s in %s", f.Severity, f.Description, f.FilePath))
		}
	}

	var removed []string
	for _, f := range oldFindings {
		key := f.RuleID + ":" + f.FilePath
		if !newRules[key] {
			removed = append(removed, fmt.Sprintf("[%s] %s in %s", f.Severity, f.Description, f.FilePath))
		}
	}

	return DiffResult{
		NewScore:        newScore.TotalScore,
		ScoreShift:      shift,
		AddedFindings:   added,
		RemovedFindings: removed,
	}
}
