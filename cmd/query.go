package cmd

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/privacyherodev/ph-blocky/api"

	"github.com/privacyherodev/ph-blocky/log"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

//nolint:gochecknoinits
func init() {
	rootCmd.AddCommand(queryCmd)
	queryCmd.Flags().StringP("type", "t", "A", "query type (A, AAAA, ...)")
}

//nolint:gochecknoglobals
var queryCmd = &cobra.Command{
	Use:   "query <domain>",
	Args:  cobra.ExactArgs(1),
	Short: "performs DNS query",
	Run:   query,
}

func query(cmd *cobra.Command, args []string) {
	typeFlag, _ := cmd.Flags().GetString("type")
	qType := dns.StringToType[typeFlag]

	if qType == dns.TypeNone {
		log.Logger.Fatalf("unknown query type '%s'", typeFlag)
	}

	apiRequest := api.QueryRequest{
		Query: args[0],
		Type:  typeFlag,
	}
	jsonValue, _ := json.Marshal(apiRequest)

	resp, err := http.Post(apiURL(api.BlockingQueryPath), "application/json", bytes.NewBuffer(jsonValue))

	if err != nil {
		log.Logger.Fatal("can't execute", err)

		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Logger.Fatalf("NOK: %s %s", resp.Status, string(body))

		return
	}

	var result api.QueryResult
	err = json.NewDecoder(resp.Body).Decode(&result)

	if err != nil {
		log.Logger.Fatal("can't read response: ", err)

		return
	}

	log.Logger.Infof("Query result for '%s' (%s):", apiRequest.Query, apiRequest.Type)
	log.Logger.Infof("\treason:        %20s", result.Reason)
	log.Logger.Infof("\tresponse type: %20s", result.ResponseType)
	log.Logger.Infof("\tresponse:      %20s", result.Response)
	log.Logger.Infof("\treturn code:   %20s", result.ReturnCode)
}
