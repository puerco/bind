package cmd

import (
	"github.com/spf13/cobra"
)

func addExtract(parentCmd *cobra.Command) {
	extractCmd := &cobra.Command{
		Short:             "extract data from sigstore bundles",
		Use:               "extract [attestation | predicate] bundle.json",
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
	}

	addExtractAttestation(extractCmd)
	addExtractPredicate(extractCmd)

	parentCmd.AddCommand(extractCmd)
}
