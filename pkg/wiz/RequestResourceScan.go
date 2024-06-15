package wiz

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/machinebox/graphql"
)

func RequestResourceScan(token, apiURL, id string) (interface{}, error) {
	graphqlClient := graphql.NewClient(apiURL)
	graphqlRequest := graphql.NewRequest(`
        mutation RequestResourceScan($input: RequestConnectorEntityScanInput!) {
          requestConnectorEntityScan(input: $input) {
            success
            reason
            scan {
              id
            }
          }
        }
    `)

	// Prepare the variables
	variablesJSON := fmt.Sprintf(`{
		"input":{
				"id":"%s",
				"type":"SUBSCRIPTION"
		}
	}`, id)

	var variables map[string]interface{}
	if err := json.Unmarshal([]byte(variablesJSON), &variables); err != nil {
		return nil, err
	}

	for k, v := range variables {
		graphqlRequest.Var(k, v)
	}

	graphqlRequest.Header.Set("Authorization", "Bearer "+token)

	var graphqlResponse interface{}
	if err := graphqlClient.Run(context.Background(), graphqlRequest, &graphqlResponse); err != nil {
		return nil, err
	}

	return graphqlResponse, nil
}
