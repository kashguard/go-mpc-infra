package probe

import (
	"github.com/kashguard/go-mpc-wallet/internal/util/command"
	"github.com/spf13/cobra"
)

const (
	verboseFlag string = "verbose"
)

func New() *cobra.Command {
	return command.NewSubcommandGroup("probe",
		newLiveness(),
		newReadiness(),
	)
}
