package wiz

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DanMolz/wiz-gadget/models"
	"github.com/machinebox/graphql"
)

func SystemActivityLogTable(token, apiURL, id string) (models.SystemActivityResponse, error) {
	graphqlClient := graphql.NewClient(apiURL)
	graphqlRequest := graphql.NewRequest(`
        query SystemActivityLogTable($first: Int, $after: String, $filterBy: SystemActivityFilters) {
          systemActivities(first: $first, after: $after, filterBy: $filterBy) {
            nodes {
              id
              name
              triggerType
              triggeredBy {
                ... on SystemActivityUserSnapshot {
                  id
                  name
                }
                ... on SystemActivityServiceAccountSnapshot {
                  id
                  name
                }
                ... on SystemActivitySystemTrigger {
                  id
                }
              }
              createdAt
              startedAt
              endedAt
              status
              statusInfo
              context {
                ... on SystemActivityScanContext {
                  connector {
                    id
                    name
                    type {
                      id
                      name
                    }
                  }
                  scannedEntity {
                    ...SystemActivityGraphEntitySnapshot
                  }
                  code {
                    ...SystemActivityScanContextCodeAnalyzerDetails
                  }
                }
                ... on SystemActivityAnalyzerContext {
                  name
                }
                ... on SystemActivityUninstallOutpostContext {
                  stage
                  cluster {
                    name
                    region
                  }
                  outpost {
                    id
                    name
                    serviceType
                  }
                }
                ... on SystemActivityReassessIssueContext {
                  reassessIssue: issue {
                    controlName
                  }
                  resource {
                    name
                    nativeType
                    type
                  }
                }
                ... on SystemActivityIntegrationActionContext {
                  integrationAction: action {
                    id
                    type
                    params
                  }
                  integration {
                    id
                    name
                    type
                  }
                  rule {
                    id
                    name
                  }
                  integrationActionProjects: projects {
                    id
                    name
                  }
                  integrationActionIssue: issue {
                    id
                    controlName
                  }
                  integrationActionControl: control {
                    id
                    name
                  }
                  entity {
                    ...SystemActivityGraphEntitySnapshot
                  }
                }
                ... on SystemActivityCopyResourceForensicsContext {
                  resourceName
                  copyResourceEntity: entity {
                    ...SystemActivityGraphEntitySnapshot
                  }
                }
                ... on SystemActivitySecurityGraphControlRunContext {
                  control {
                    id
                    name
                  }
                  projects {
                    id
                    name
                  }
                }
                ... on SystemActivityEnrichmentIntegrationContext {
                  ingestionIntegration: integration {
                    id
                    name
                  }
                  fileUploadId
                }
                ... on SystemActivityPreviewHubContext {
                  previewHubItem {
                    id
                    title
                    enabled
                  }
                }
                ... on SystemActivityRemediationCatalogContext {
                  responseActionGateway: gateway {
                    id
                    deploymentName
                    project {
                      id
                      name
                    }
                  }
                  deployment {
                    id
                    name
                    type
                  }
                }
                ... on SystemActivityRemediationActionRunContext {
                  automationRule {
                    id
                    name
                  }
                  responseActionSnapshot {
                    id
                    name
                    description
                    isDisruptive
                    target {
                      entityType
                      sourceRule {
                        ... on SystemActivityCloudConfigurationRuleSnapshot {
                          id
                          name
                        }
                        ... on SystemActivityControlSnapshot {
                          id
                          name
                        }
                        ... on SystemActivityCloudEventRuleSnapshot {
                          id
                          name
                        }
                      }
                    }
                  }
                  target {
                    graphEntity {
                      ...SystemActivityGraphEntitySnapshot
                    }
                    configurationFinding {
                      id
                      name
                    }
                  }
                }
                ... on SystemActivityRuntimeResponsePolicyEnforcementContext {
                  sensor {
                    id
                    projects {
                      id
                      name
                      slug
                      isFolder
                    }
                  }
                  runtimeResponsePolicies {
                    id
                    name
                    project {
                      id
                      name
                      slug
                      isFolder
                    }
                  }
                }
              }
              result {
                ... on SystemActivityCopyResourceForensicsResult {
                  copiedResourceUrl
                  copiedResourcesGroupUrl
                }
                ... on SystemActivityEnrichmentIntegrationResult {
                  dataSources {
                    ...IngestionStatsDetails
                  }
                  findings {
                    ...IngestionStatsDetails
                  }
                  events {
                    ...IngestionStatsDetails
                  }
                  tags {
                    ...IngestionStatsDetails
                  }
                  unresolvedAssets {
                    count
                  }
                }
                ... on SystemActivityUninstallOutpostResult {
                  value
                }
                ... on SystemActivityRemediationCatalogResult {
                  catalog
                  catalogVersion
                }
                ... on SystemActivityRunResponseActionResult {
                  result
                }
              }
            }
            pageInfo {
              hasNextPage
              endCursor
            }
            totalCount
          }
        }

            fragment SystemActivityGraphEntitySnapshot on SystemActivityGraphEntitySnapshot {
          id
          name
          type
          nativeType
        }


            fragment SystemActivityScanContextCodeAnalyzerDetails on SystemActivityScanContextCodeAnalyzerDetails {
          webhookEvent {
            ...WebhookEventDetails
          }
          commit {
            ...VersionControlCommitDetails
          }
          pullRequest {
            ...VersionControlPullRequestDetails
          }
        }


            fragment WebhookEventDetails on WebhookEvent {
          source
          type
          createdAt
          receivedAt
          processedAt
          wizRequestID
          sourceRequestID
          hookID
        }


            fragment VersionControlCommitDetails on VersionControlCommit {
          author
          infoURL
          messageSnippet
          ref
          sha
        }


            fragment VersionControlPullRequestDetails on VersionControlPullRequest {
          id
          infoURL
          author
          baseCommit {
            ...VersionControlCommitDetails
          }
          headCommit {
            ...VersionControlCommitDetails
          }
          title
          bodySnippet
          analytics {
            additions
            changedFiles
            comments
            commits
            deletions
            reviewComments
          }
        }


            fragment IngestionStatsDetails on EnrichmentIntegrationStats {
          incoming
          handled
        }
    `)

	// Prepare the variables
	variablesJSON := fmt.Sprintf(`{
    "first":20,
    "filterBy":{
        "resourceId":[
          "%s"
        ],
        "status":[
          "IN_PROGRESS"
        ]
    }
  }`, id)

	var variables map[string]interface{}
	if err := json.Unmarshal([]byte(variablesJSON), &variables); err != nil {
		return models.SystemActivityResponse{}, err
	}

	for k, v := range variables {
		graphqlRequest.Var(k, v)
	}

	graphqlRequest.Header.Set("Authorization", "Bearer "+token)

	var graphqlResponse interface{}
	if err := graphqlClient.Run(context.Background(), graphqlRequest, &graphqlResponse); err != nil {
		return models.SystemActivityResponse{}, err
	}

	// Convert the interface{} response to JSON
	responseJSON, err := json.Marshal(graphqlResponse)
	if err != nil {
		return models.SystemActivityResponse{}, err
	}

	// Unmarshal the JSON into the SystemActivityResponse struct
	var systemActivityResposne models.SystemActivityResponse
	if err := json.Unmarshal(responseJSON, &systemActivityResposne); err != nil {
		return models.SystemActivityResponse{}, err
	}

	return systemActivityResposne, nil
}
