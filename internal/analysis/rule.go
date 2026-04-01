package analysis

type Rule interface {
	ID() string
	Name() string
	Description() string
	Analyze(node interface{}, report func(Finding))
}
