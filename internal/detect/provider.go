package detect

// Provider contributes a named set of detection rules to a Detector.
// Implementations are pure values: no I/O, no config, no init() side
// effects. Adding a new rule source = add one file declaring a struct
// that satisfies this interface, then append it to DefaultProviders.
type Provider interface {
	Name() string
	Rules() []Rule
}

// DefaultProviders returns the providers used when New is called with
// no explicit providers. Order is significant: when two rules match the
// same byte span, first-provider-wins dedup applies (see detect.go).
func DefaultProviders() []Provider {
	return []Provider{
		builtinProvider{},
		llmProvider{},
		cloudProvider{},
		chatProvider{},
		gitProvider{},
		devtoolsProvider{},
	}
}
