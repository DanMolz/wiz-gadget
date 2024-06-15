package models

import "time"

// WebhookPayload represents the structure of the incoming webhook payload
type WebhookPayload struct {
	Event struct {
		Actor struct {
			IP       string `json:"IP"`
			ActingAs struct {
				Name             string `json:"name"`
				ProviderUniqueID string `json:"providerUniqueId"`
				Type             string `json:"type"`
			} `json:"actingAs"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"actor"`
		Category        string `json:"category"`
		CloudPlatform   string `json:"cloudPlatform"`
		EventURL        string `json:"eventURL"`
		MatchedRules    string `json:"matchedRules"`
		Name            string `json:"name"`
		Path            any    `json:"path"`
		Source          string `json:"source"`
		SubjectResource struct {
			AccountExternalID   string `json:"account_external_id"`
			AccountName         string `json:"account_name"`
			AccountProvider     string `json:"account_provider"`
			ExternalID          string `json:"externalId"`
			KubernetesCluster   string `json:"kubernetesCluster"`
			KubernetesNamespace string `json:"kubernetesNamespace"`
			Name                string `json:"name"`
			ProviderUniqueID    string `json:"providerUniqueId"`
			Region              string `json:"region"`
			Type                string `json:"type"`
		} `json:"subjectResource"`
		Timestamp time.Time `json:"timestamp"`
	} `json:"event"`
	Trigger struct {
		RuleID   string `json:"ruleId"`
		RuleName string `json:"ruleName"`
		Source   string `json:"source"`
		Type     string `json:"type"`
	} `json:"trigger"`
}

type CloudAccountsResponse struct {
	CloudAccounts struct {
		Nodes []struct {
			CloudProvider                  string    `json:"cloudProvider"`
			ContainerCount                 int       `json:"containerCount"`
			CriticalSystemHealthIssueCount int       `json:"criticalSystemHealthIssueCount"`
			ExternalID                     string    `json:"externalId"`
			FirstScannedAt                 time.Time `json:"firstScannedAt"`
			HighSystemHealthIssueCount     int       `json:"highSystemHealthIssueCount"`
			ID                             string    `json:"id"`
			LastScannedAt                  time.Time `json:"lastScannedAt"`
			LinkedProjects                 []struct {
				ID          string `json:"id"`
				IsFolder    bool   `json:"isFolder"`
				Name        string `json:"name"`
				RiskProfile struct {
					BusinessImpact string `json:"businessImpact"`
				} `json:"riskProfile"`
				Slug string `json:"slug"`
			} `json:"linkedProjects"`
			LowSystemHealthIssueCount    int    `json:"lowSystemHealthIssueCount"`
			MediumSystemHealthIssueCount int    `json:"mediumSystemHealthIssueCount"`
			Name                         string `json:"name"`
			SourceDeployments            []struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Status string `json:"status"`
				Type   string `json:"type"`
			} `json:"sourceDeployments"`
			VirtualMachineCount int `json:"virtualMachineCount"`
		} `json:"nodes"`
		PageInfo struct {
			EndCursor   string `json:"endCursor"`
			HasNextPage bool   `json:"hasNextPage"`
		} `json:"pageInfo"`
		TotalCount int `json:"totalCount"`
	} `json:"cloudAccounts"`
}

type SystemActivityResponse struct {
	SystemActivities struct {
		Nodes []struct {
			Context struct {
				Code      any `json:"code"`
				Connector struct {
					ID   string `json:"id"`
					Name string `json:"name"`
					Type struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"type"`
				} `json:"connector"`
				ScannedEntity struct {
					ID         string `json:"id"`
					Name       string `json:"name"`
					NativeType string `json:"nativeType"`
					Type       string `json:"type"`
				} `json:"scannedEntity"`
			} `json:"context"`
			CreatedAt   time.Time `json:"createdAt"`
			EndedAt     any       `json:"endedAt"`
			ID          string    `json:"id"`
			Name        string    `json:"name"`
			Result      any       `json:"result"`
			StartedAt   time.Time `json:"startedAt"`
			Status      string    `json:"status"`
			StatusInfo  any       `json:"statusInfo"`
			TriggerType string    `json:"triggerType"`
			TriggeredBy struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"triggeredBy"`
		} `json:"nodes"`
		PageInfo struct {
			EndCursor   string `json:"endCursor"`
			HasNextPage bool   `json:"hasNextPage"`
		} `json:"pageInfo"`
		TotalCount int `json:"totalCount"`
	} `json:"systemActivities"`
}
