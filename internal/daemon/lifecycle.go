package daemon

// LogName is the daemon's stdio log file, relative to $OPENSECRETMASK_HOME.
// TODO(task-2): moves to state.go beside the pidfile name; delete this line
// there.
const LogName = "daemon.log"

// SpawnConfig is everything needed to start a daemon. Key is the store
// passphrase, handed to the spawned process via $OSM_KEY: this package never
// prompts, so adapters resolve it from the environment or a terminal first.
type SpawnConfig struct {
	Home          string
	Listen        string
	Dash          string
	Key           string
	Extra         []string
	Entropy       bool
	LogLevel      string
	AllowExternal bool
}

// args renders the 'osm proxy' argv for this configuration. An empty LogLevel
// falls back to info: a record written by an older binary may not carry one,
// and 'osm proxy' rejects an empty --log-level.
func (c SpawnConfig) args() []string {
	logLevel := c.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	args := []string{"proxy", "--listen", c.Listen, "--dashboard", c.Dash, "--log-level", logLevel}
	for _, p := range c.Extra {
		args = append(args, "--provider", p)
	}
	if c.Entropy {
		args = append(args, "--detect-entropy")
	}
	if c.AllowExternal {
		args = append(args, "--allow-external-bind")
	}
	return args
}
