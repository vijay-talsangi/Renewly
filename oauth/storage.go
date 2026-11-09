// Package oauth contains the PostgreSQL persistence layer used by Fosite.
// It deliberately stores Fosite token signatures, never bearer-token values.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/fosite"
	oauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"
	fositeStorage "github.com/ory/fosite/storage"
)

const (
	authorizationCode = "authorization_code"
	accessToken       = "access_token"
	refreshToken      = "refresh_token"
)

type txContextKey struct{}

// PostgresStorage implements Fosite's OAuth2 storage, client manager,
// revocation storage, and transaction interfaces.
type PostgresStorage struct {
	pool *pgxpool.Pool
}

var (
	_ fositeStorage.Transactional   = (*PostgresStorage)(nil)
	_ oauth2.TokenRevocationStorage = (*PostgresStorage)(nil)
	_ pkce.PKCERequestStorage       = (*PostgresStorage)(nil)
	_ fosite.ClientManager          = (*PostgresStorage)(nil)
)

func NewPostgresStorage(pool *pgxpool.Pool) *PostgresStorage {
	return &PostgresStorage{pool: pool}
}

type dbtx interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *PostgresStorage) executor(ctx context.Context) dbtx {
	if tx, ok := ctx.Value(txContextKey{}).(pgx.Tx); ok {
		return tx
	}
	return s.pool
}

func (s *PostgresStorage) BeginTX(ctx context.Context) (context.Context, error) {
	if _, ok := ctx.Value(txContextKey{}).(pgx.Tx); ok {
		return nil, errors.New("oauth transaction already exists in context")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, txContextKey{}, tx), nil
}

func (s *PostgresStorage) Commit(ctx context.Context) error {
	tx, ok := ctx.Value(txContextKey{}).(pgx.Tx)
	if !ok {
		return errors.New("oauth transaction missing from context")
	}
	return tx.Commit(ctx)
}

func (s *PostgresStorage) Rollback(ctx context.Context) error {
	tx, ok := ctx.Value(txContextKey{}).(pgx.Tx)
	if !ok {
		return errors.New("oauth transaction missing from context")
	}
	return tx.Rollback(ctx)
}

type storedRequest struct {
	ID                string                 `json:"id"`
	RequestedAt       time.Time              `json:"requested_at"`
	Client            *fosite.DefaultClient  `json:"client"`
	RequestedScope    fosite.Arguments       `json:"requested_scope"`
	GrantedScope      fosite.Arguments       `json:"granted_scope"`
	Form              url.Values             `json:"form"`
	Session           *fosite.DefaultSession `json:"session"`
	RequestedAudience fosite.Arguments       `json:"requested_audience"`
	GrantedAudience   fosite.Arguments       `json:"granted_audience"`
}

func encodeRequester(request fosite.Requester) ([]byte, error) {
	if request == nil || request.GetClient() == nil {
		return nil, errors.New("cannot persist an incomplete OAuth request")
	}
	client, ok := request.GetClient().(*fosite.DefaultClient)
	if !ok {
		return nil, fmt.Errorf("unsupported Fosite client type %T", request.GetClient())
	}
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok {
		return nil, fmt.Errorf("unsupported Fosite session type %T", request.GetSession())
	}
	payload := storedRequest{
		ID: request.GetID(), RequestedAt: request.GetRequestedAt(), Client: client,
		RequestedScope: request.GetRequestedScopes(), GrantedScope: request.GetGrantedScopes(),
		Form: request.GetRequestForm(), Session: session,
		RequestedAudience: request.GetRequestedAudience(), GrantedAudience: request.GetGrantedAudience(),
	}
	return json.Marshal(payload)
}

func decodeRequester(payload []byte) (fosite.Requester, error) {
	var stored storedRequest
	if err := json.Unmarshal(payload, &stored); err != nil {
		return nil, fmt.Errorf("decode OAuth session: %w", err)
	}
	if stored.Client == nil || stored.Session == nil {
		return nil, errors.New("stored OAuth session is missing client or session")
	}
	return &fosite.Request{
		ID: stored.ID, RequestedAt: stored.RequestedAt, Client: stored.Client,
		RequestedScope: stored.RequestedScope, GrantedScope: stored.GrantedScope,
		Form: stored.Form, Session: stored.Session,
		RequestedAudience: stored.RequestedAudience, GrantedAudience: stored.GrantedAudience,
	}, nil
}

func sessionExpiry(request fosite.Requester, candidates ...fosite.TokenType) (time.Time, error) {
	if request == nil || request.GetSession() == nil {
		return time.Time{}, errors.New("OAuth request has no session")
	}
	for _, typ := range candidates {
		if expiry := request.GetSession().GetExpiresAt(typ); !expiry.IsZero() {
			return expiry, nil
		}
	}
	return time.Time{}, errors.New("OAuth session has no expiry for token type")
}

func (s *PostgresStorage) createSession(ctx context.Context, signature, tokenType, accessSig string, request fosite.Requester, expiry time.Time) error {
	payload, err := encodeRequester(request)
	if err != nil {
		return err
	}
	_, err = s.executor(ctx).Exec(ctx, `
		INSERT INTO oauth_sessions
		(signature, token_type, request_id, client_id, access_signature, payload, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		signature, tokenType, request.GetID(), request.GetClient().GetID(), nullableString(accessSig), payload, expiry)
	if err != nil {
		return fmt.Errorf("persist OAuth %s: %w", tokenType, err)
	}
	return nil
}

func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func (s *PostgresStorage) loadSession(ctx context.Context, signature, tokenType string) (fosite.Requester, bool, error) {
	var payload []byte
	var invalidated, revoked *time.Time
	var expires time.Time
	err := s.executor(ctx).QueryRow(ctx, `
		SELECT payload, invalidated_at, revoked_at, expires_at
		FROM oauth_sessions WHERE signature=$1 AND token_type=$2`, signature, tokenType).
		Scan(&payload, &invalidated, &revoked, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fosite.ErrNotFound
	}
	if err != nil {
		return nil, false, err
	}
	request, err := decodeRequester(payload)
	if err != nil {
		return nil, false, err
	}
	active := invalidated == nil && revoked == nil && time.Now().Before(expires)
	return request, active, nil
}

func (s *PostgresStorage) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	expiry, err := sessionExpiry(request, fosite.AuthorizeCode)
	if err != nil {
		return err
	}
	return s.createSession(ctx, code, authorizationCode, "", request, expiry)
}

func (s *PostgresStorage) GetAuthorizeCodeSession(ctx context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	request, active, err := s.loadSession(ctx, code, authorizationCode)
	if err != nil {
		return nil, err
	}
	if !active {
		return request, fosite.ErrInvalidatedAuthorizeCode
	}
	return request, nil
}

func (s *PostgresStorage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	tag, err := s.executor(ctx).Exec(ctx, `UPDATE oauth_sessions SET invalidated_at=NOW() WHERE signature=$1 AND token_type=$2`, code, authorizationCode)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fosite.ErrNotFound
	}
	return nil
}

func (s *PostgresStorage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	expiry, err := sessionExpiry(request, fosite.AccessToken)
	if err != nil {
		return err
	}
	return s.createSession(ctx, signature, accessToken, "", request, expiry)
}

func (s *PostgresStorage) GetAccessTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	request, active, err := s.loadSession(ctx, signature, accessToken)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, fosite.ErrInactiveToken
	}
	return request, nil
}

func (s *PostgresStorage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	_, err := s.executor(ctx).Exec(ctx, `DELETE FROM oauth_sessions WHERE signature=$1 AND token_type=$2`, signature, accessToken)
	return err
}

func (s *PostgresStorage) CreateRefreshTokenSession(ctx context.Context, signature, accessSignature string, request fosite.Requester) error {
	expiry, err := sessionExpiry(request, fosite.RefreshToken)
	if err != nil {
		return err
	}
	return s.createSession(ctx, signature, refreshToken, accessSignature, request, expiry)
}

func (s *PostgresStorage) GetRefreshTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	request, active, err := s.loadSession(ctx, signature, refreshToken)
	if err != nil {
		return nil, err
	}
	if !active {
		return request, fosite.ErrInactiveToken
	}
	return request, nil
}

func (s *PostgresStorage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	_, err := s.executor(ctx).Exec(ctx, `DELETE FROM oauth_sessions WHERE signature=$1 AND token_type=$2`, signature, refreshToken)
	return err
}

// RotateRefreshToken invalidates the old signature exactly once. The partial
// update makes concurrent refresh attempts serialize: only one can rotate it.
func (s *PostgresStorage) RotateRefreshToken(ctx context.Context, requestID, oldSignature string) error {
	tag, err := s.executor(ctx).Exec(ctx, `
		UPDATE oauth_sessions SET invalidated_at=NOW()
		WHERE signature=$1 AND request_id=$2 AND token_type=$3
		  AND invalidated_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()`,
		oldSignature, requestID, refreshToken)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fosite.ErrSerializationFailure
	}
	return nil
}

func (s *PostgresStorage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	_, err := s.executor(ctx).Exec(ctx, `UPDATE oauth_sessions SET revoked_at=NOW() WHERE request_id=$1 AND token_type=$2 AND revoked_at IS NULL`, requestID, refreshToken)
	return err
}

func (s *PostgresStorage) RevokeAccessToken(ctx context.Context, requestID string) error {
	_, err := s.executor(ctx).Exec(ctx, `UPDATE oauth_sessions SET revoked_at=NOW() WHERE request_id=$1 AND token_type=$2 AND revoked_at IS NULL`, requestID, accessToken)
	return err
}

func (s *PostgresStorage) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var client fosite.DefaultClient
	var secret []byte
	err := s.pool.QueryRow(ctx, `SELECT client_id, client_secret_hash, redirect_uris, grant_types, response_types, scopes, audience, is_public FROM oauth_clients WHERE client_id=$1`, id).
		Scan(&client.ID, &secret, &client.RedirectURIs, &client.GrantTypes, &client.ResponseTypes, &client.Scopes, &client.Audience, &client.Public)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	client.Secret = secret
	return &client, nil
}

func (s *PostgresStorage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oauth_client_assertions WHERE jti=$1 AND expires_at > NOW())`, jti).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return fosite.ErrJTIKnown
	}
	return nil
}

func (s *PostgresStorage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO oauth_client_assertions(jti, expires_at) VALUES($1,$2)`, jti, exp)
	if err != nil {
		return fmt.Errorf("store client assertion jti: %w", err)
	}
	return nil
}

// CreatePKCERequestSession persists the PKCE challenge alongside, but separately
// from, the authorization-code row. Fosite uses the authorization-code
// signature as the PKCE key, so this must live in its own table rather than
// oauth_sessions (whose signature is already occupied by the code row).
func (s *PostgresStorage) CreatePKCERequestSession(ctx context.Context, signature string, request fosite.Requester) error {
	expiry, err := sessionExpiry(request, fosite.AuthorizeCode)
	if err != nil {
		return err
	}
	payload, err := encodeRequester(request)
	if err != nil {
		return err
	}
	_, err = s.executor(ctx).Exec(ctx, `
		INSERT INTO oauth_pkce_sessions (signature, payload, expires_at)
		VALUES ($1, $2, $3)`, signature, payload, expiry)
	if err != nil {
		return fmt.Errorf("persist OAuth PKCE session: %w", err)
	}
	return nil
}

// GetPKCERequestSession returns the PKCE request associated with an
// authorization-code signature. Expired challenges are treated as absent.
func (s *PostgresStorage) GetPKCERequestSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	var payload []byte
	var expiry time.Time
	err := s.executor(ctx).QueryRow(ctx, `
		SELECT payload, expires_at
		FROM oauth_pkce_sessions
		WHERE signature = $1 AND expires_at > NOW()`, signature).Scan(&payload, &expiry)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load OAuth PKCE session: %w", err)
	}
	request, err := decodeRequester(payload)
	if err != nil {
		return nil, err
	}
	return request, nil
}

// DeletePKCERequestSession removes the one-time PKCE challenge after Fosite
// retrieves it during authorization-code exchange.
func (s *PostgresStorage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	_, err := s.executor(ctx).Exec(ctx, `DELETE FROM oauth_pkce_sessions WHERE signature = $1`, signature)
	if err != nil {
		return fmt.Errorf("delete OAuth PKCE session: %w", err)
	}
	return nil
}
