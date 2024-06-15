package wiz

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DanMolz/wiz-gadget/models"
	"github.com/machinebox/graphql"
)

func CloudAccounts(token, apiURL, accountID string) (models.CloudAccountsResponse, error) {
	graphqlClient := graphql.NewClient(apiURL)
	graphqlRequest := graphql.NewRequest(`
        query CloudAccountsPage($filterBy: CloudAccountFilters, $first: Int, $after: String) {
          cloudAccounts(filterBy: $filterBy, first: $first, after: $after) {
            nodes {
              id
              name
              externalId
              cloudProvider
              firstScannedAt
              lastScannedAt
              virtualMachineCount
              containerCount
              sourceDeployments {
                id
                name
                status
                type
              }
              linkedProjects {
                id
                name
                slug
                isFolder
                riskProfile {
                  businessImpact
                }
              }
              criticalSystemHealthIssueCount
              highSystemHealthIssueCount
              mediumSystemHealthIssueCount
              lowSystemHealthIssueCount
            }
            pageInfo {
              hasNextPage
              endCursor
            }
            totalCount
          }
        }
    `)

	// Prepare the variables
	variablesJSON := fmt.Sprintf(`{
      "first": 1,
      "filterBy": {
        "search": [
          "%s"
        ]
      }
    }`, accountID)

	var variables map[string]interface{}
	if err := json.Unmarshal([]byte(variablesJSON), &variables); err != nil {
		return models.CloudAccountsResponse{}, err
	}

	for k, v := range variables {
		graphqlRequest.Var(k, v)
	}

	graphqlRequest.Header.Set("Authorization", "Bearer "+token)

	var graphqlResponse interface{}
	if err := graphqlClient.Run(context.Background(), graphqlRequest, &graphqlResponse); err != nil {
		return models.CloudAccountsResponse{}, err
	}

	// Convert the interface{} response to JSON
	responseJSON, err := json.Marshal(graphqlResponse)
	if err != nil {
		return models.CloudAccountsResponse{}, err
	}

	// Unmarshal the JSON into the CloudAccountsResponse struct
	var cloudAccountsResponse models.CloudAccountsResponse
	if err := json.Unmarshal(responseJSON, &cloudAccountsResponse); err != nil {
		return models.CloudAccountsResponse{}, err
	}

	return cloudAccountsResponse, nil
}
