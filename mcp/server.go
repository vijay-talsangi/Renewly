// Package mcp handles mcp server
package mcp

import (
	"net/http"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	db "github.com/vijay-talsangi/Renewly/db/sqlc"
	"github.com/vijay-talsangi/Renewly/mcp/tools"
	"github.com/vijay-talsangi/Renewly/middleware"
)

func NewHTTPHandler(queries *db.Queries) http.Handler {
	return sdk.NewStreamableHTTPHandler(
		func(r *http.Request) *sdk.Server {
			userID, ok := middleware.UserIDFromContext(r.Context())

			server := sdk.NewServer(
				&sdk.Implementation{
					Name:    "renewly",
					Version: "1.0.0",
				},
				nil,
			)

			if ok {
				tools.RegisterSubscriptionTools(server, queries, userID)
			}

			return server
		},
		&sdk.StreamableHTTPOptions{
			Stateless:    true,
			JSONResponse: true,
		},
	)
}
