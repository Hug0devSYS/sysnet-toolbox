// Command syslog-triage clusters syslog and journald messages into
// templates with the Drain algorithm, then reports the dominant patterns,
// volume spikes (per pattern and overall) and patterns never seen before.
//
// It only reads logs; the optional pattern model is written only with
// --update-model.
package main

import (
	"os"

	"github.com/Hug0devSYS/sysnet-toolbox/tools/syslog-triage/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], cli.DefaultEnv()))
}
