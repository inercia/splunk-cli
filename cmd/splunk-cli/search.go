package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/inercia/splunk-cli/pkg/splunk"

	"github.com/spf13/cobra"
)

var (
	earliestFlag string
	latestFlag   string
	timeoutFlag  int
)

func init() {
	searchCmd.Flags().StringVar(&earliestFlag, "earliest", "", "Earliest time (e.g., -24h@h)")
	searchCmd.Flags().StringVar(&latestFlag, "latest", "", "Latest time (e.g., now)")
	searchCmd.Flags().IntVar(&timeoutFlag, "timeout", 120, "Timeout in seconds for the overall search")
	rootCmd.AddCommand(searchCmd)
}

var searchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Run a Splunk search",
	Long:  "Run a Splunk search query and print the results.",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("please provide a search query")
		}
		query := strings.Join(args, " ")

		client, err := newClientFromFlagsAndEnv(cmd)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(timeoutFlag)*time.Second)
		defer cancel()
		results, err := client.Search(ctx, query, splunk.JobOptions{
			EarliestTime: earliestFlag,
			LatestTime:   latestFlag,
		})
		if err != nil {
			return err
		}

		printResultsTable(results)
		return nil
	},
}

func printResultsTable(results *splunk.SearchResults) {
	if results == nil || len(results.Records) == 0 {
		fmt.Println("No results.")
		return
	}

	// Determine columns. Prefer provided fields; else derive from first record.
	columns := results.Fields
	if len(columns) == 0 && len(results.Records) > 0 {
		for k := range results.Records[0] {
			columns = append(columns, k)
		}
		sort.Strings(columns)
	}

	// Compute column widths
	widths := make([]int, len(columns))
	for i, col := range columns {
		widths[i] = len(col)
	}
	for _, rec := range results.Records {
		for i, col := range columns {
			val := rec[col]
			if l := len(val); l > widths[i] {
				widths[i] = l
			}
		}
	}

	// Print header
	for i, col := range columns {
		fmt.Fprint(os.Stdout, padRight(col, widths[i]))
		if i < len(columns)-1 {
			fmt.Fprint(os.Stdout, "  ")
		}
	}
	fmt.Fprintln(os.Stdout)
	// Print separator
	for i := range columns {
		fmt.Fprint(os.Stdout, strings.Repeat("-", widths[i]))
		if i < len(columns)-1 {
			fmt.Fprint(os.Stdout, "  ")
		}
	}
	fmt.Fprintln(os.Stdout)
	// Print rows
	for _, rec := range results.Records {
		for i, col := range columns {
			fmt.Fprint(os.Stdout, padRight(rec[col], widths[i]))
			if i < len(columns)-1 {
				fmt.Fprint(os.Stdout, "  ")
			}
		}
		fmt.Fprintln(os.Stdout)
	}
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}
