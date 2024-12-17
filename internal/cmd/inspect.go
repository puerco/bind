package cmd

import (
	"errors"
	"fmt"

	"github.com/puerco/bind/pkg/bundle"
	"github.com/spf13/cobra"
)

type inspectOptions struct {
	bundleOptions
}

// Validates the options in context with arguments
func (o *inspectOptions) Validate() error {
	return errors.Join(
		o.bundleOptions.Validate(),
	)
}

func (o *inspectOptions) AddFlags(cmd *cobra.Command) {
	o.bundleOptions.AddFlags(cmd)
}

func addInspect(parentCmd *cobra.Command) {
	opts := inspectOptions{}
	extractCmd := &cobra.Command{
		Short:             "prints useful information about a bundle",
		Use:               "inspect",
		Example:           fmt.Sprintf("%s inspect bundle.json ", appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				if err := opts.SetBundlePath(args[0]); err != nil {
					return err
				}
			}

			if err := opts.Validate(); err != nil {
				return err
			}

			reader, closer, err := opts.OpenBundle()
			if err != nil {
				return fmt.Errorf("opening bundle: %w", err)
			}
			defer closer()

			tool := bundle.NewTool()

			b, err := tool.ParseBundle(reader)
			if err != nil {
				return fmt.Errorf("parsing bundle: %w", err)
			}

			mediatype, errPred := tool.ExtractPredicateType(b)
			mtMsg := mediatype
			if errPred != nil {
				mtMsg = fmt.Sprintf("error fetching media type: %s", errPred.Error())
			}

			fmt.Printf("\nBundle information:\n\n")
			fmt.Printf("Media Type:     %s\n", b.MediaType)
			fmt.Printf("Predicate Type: %s\n\n", mtMsg)

			return nil
		},
	}
	opts.AddFlags(extractCmd)
	parentCmd.AddCommand(extractCmd)
}
