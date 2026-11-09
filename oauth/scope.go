package oauth

import "github.com/vijay-talsangi/Renewly/internal/webui"

// scopeDefinition is the user-facing description of a scope. The "renewly"
// scope grants the MCP tools registered in mcp/tools: list_subscriptions,
// get_subscription, get_upcoming_bills (read) and create_subscription,
// update_subscription, cancel_subscription (write). The consent UI therefore
// always labels both read and write capabilities; it never presents the scope
// as read-only.
type scopeDefinition struct {
	Label       string
	Description string
	Read        []string
	Write       []string
	Offline     bool
}

var supportedScopeDefinitions = map[string]scopeDefinition{
	"renewly": {
		Label:       "Your Renewly subscriptions",
		Description: "This application can read your subscription data and make changes to it on your behalf.",
		Read: []string{
			"View your subscriptions",
			"View subscription details",
			"View upcoming bills",
		},
		Write: []string{
			"Create new subscriptions",
			"Update existing subscriptions",
			"Cancel subscriptions",
		},
	},
	"offline_access": {
		Label:       "Stay connected after you close this window",
		Description: "This application can refresh its access without asking you to sign in again. You can revoke this access later.",
		Offline:     true,
	},
}

// scopeViews returns descriptions only for scopes Renewly actually supports
// and the authorization request actually asked for.
func scopeViews(requested []string) []webui.ScopeView {
	views := make([]webui.ScopeView, 0, len(requested))
	for _, scope := range requested {
		definition, ok := supportedScopeDefinitions[scope]
		if !ok {
			continue
		}
		views = append(views, webui.ScopeView{
			Name:        scope,
			Label:       definition.Label,
			Description: definition.Description,
			Read:        definition.Read,
			Write:       definition.Write,
			Offline:     definition.Offline,
		})
	}
	return views
}
