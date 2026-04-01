package scoring

import (
	"github.com/phalanx-security/phalanx/internal/analysis"
	"github.com/phalanx-security/phalanx/internal/config"
)

type ScoreResult struct {
	TotalScore int
	Breakdown  map[string]int
	Action     string // "ALLOW", "WARN", "BLOCK"
}

func CalculateScore(findings []analysis.Finding) ScoreResult {
	score := 0
	breakdown := make(map[string]int)

	for _, f := range findings {
		weight := 0
		switch f.Severity {
		case "LOW":
			weight = 10
		case "MEDIUM":
			weight = 25
		case "HIGH":
			weight = 50
		case "CRITICAL":
			weight = 100
		}
		score += weight
		breakdown[f.RuleID] += weight
	}

	if score > 100 {
		score = 100
	}

	// Read thresholds from config — fall back to safe defaults if not set
	blockThreshold := 60
	warnThreshold := 30
	if cfg, err := config.GetConfig(); err == nil {
		if cfg.Policy.BlockScore > 0 {
			blockThreshold = cfg.Policy.BlockScore
		}
		if cfg.Policy.WarnScore > 0 {
			warnThreshold = cfg.Policy.WarnScore
		}
	}

	action := "ALLOW"
	if score >= blockThreshold {
		action = "BLOCK"
	} else if score >= warnThreshold {
		action = "WARN"
	}

	return ScoreResult{
		TotalScore: score,
		Breakdown:  breakdown,
		Action:     action,
	}
}
