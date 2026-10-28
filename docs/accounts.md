# Individual accounts

Default hosted authentication now uses Supabase Auth. The old shared operator token is not accepted in Supabase mode, even if the old environment variable remains configured. No framework, CDN, inline script/style or external browser network permission was added. All browser auth traffic goes through the same-origin Flask endpoints. The included Supabase URL and `sb_publishable_` key are public identifiers, not privileged credentials. No service-role, JWT-signing or database secret is required by the app for Auth.

## Roles

- Guest: public synthetic dashboard, runbooks and audit views.
- Viewer: individual verified account with read-only access.
- Operator: inject demo faults, run detection/dry-run and engage/release the kill switch.
- Approver: approve/deny/revoke plans; cannot inject faults or start unrelated runs.
- Admin: operator + approver permissions, plus account role administration at `/accounts`.

Admins cannot change their own role. New accounts are viewers. A normal account cannot change `app_metadata`; the server and SQL helpers never trust `user_metadata`, browser role labels, or role claims cached in the JWT. Admin role changes are recorded in an append-only private history table. The first 100 newest accounts are listed by the admin page; pagination is future work.

## Setup for this deployment

1. Deploy the latest GitHub commit on Render using the existing Gunicorn command. It already forwards the HTTPS scheme correctly. No new database secret or Python dependency is required.
2. In Supabase Authentication → URL Configuration, set **Site URL** to `https://aegiesops.onrender.com/` and add that URL to the allowed redirect URLs. Email confirmation may otherwise send users to an old localhost redirect. Confirmation tokens are not used to grant roles in the browser; users sign in after verifying their email.
3. In Supabase Authentication → Email/SMTP settings, configure custom SMTP before opening signup to the public. Supabase's built-in mail service only delivers to pre-authorized project-team email addresses and has strict rate limits. Keep email confirmation enabled. SMTP credentials belong in Supabase's dashboard, never in GitHub or chat. See https://supabase.com/docs/guides/auth/auth-smtp .
4. Sign up from the website and confirm your email. You initially receive viewer access.
5. A project owner must bootstrap the first admin using Supabase SQL Editor. Replace the email below with the owner's verified account. Do not automatically grant admin to the first registrant:

```sql
UPDATE auth.users
SET raw_app_meta_data = jsonb_set(coalesce(raw_app_meta_data, '{}'::jsonb), '{aegisops_role}', '"admin"'::jsonb)
WHERE lower(email) = lower('YOUR_VERIFIED_OWNER_EMAIL')
  AND email_confirmed_at IS NOT NULL AND NOT is_anonymous;
```

Confirm exactly one intended account was updated. Subsequent role assignments should use **Manage access** so they are audited. Sign in again or reload the page after bootstrap; the backend reads the current database role on every request.

No admin user was created or password chosen by the implementation. No confirmation emails were sent during tests.

## Configuration

- `AEGISOPS_AUTH_MODE`: defaults to `supabase`. Explicit `token` is retained only for existing local tests/CLI smoke and deliberate local rollback; do not use it for a shared public deployment.
- `AEGISOPS_SUPABASE_URL`: optional HTTPS-origin override (default: configured Aegis project).
- `AEGISOPS_SUPABASE_PUBLISHABLE_KEY`: optional publishable-key override. Secret keys are rejected.
- Existing `AEGISOPS_DATABASE_URL`: keep its current SQLite setting. This upgrade connects identity to Supabase; it does not migrate the remediation event store to PostgreSQL.

Tests that explicitly pass `operator_token` into `create_app` retain the old local test path. The hosted default does not fall back to that token if Supabase is unavailable.

## Security boundary

Supabase PostgREST validates the bearer JWT before invoking invoker RPC wrappers. Narrow SECURITY DEFINER implementations live in a non-exposed private schema with fixed search paths. They require a matching authenticated `auth.uid()`, an unexpired JWT, a live matching `auth.sessions` row, an unbanned non-anonymous user, and confirmed email. Roles are read fresh from administrator-controlled app metadata. An outage fails control requests closed with 503. Role removal takes effect at the next HTTP authorization check; it does not retroactively cancel an already-authorized engine execution.

Authenticated control, sign-out and admin operations require bearer auth plus the existing same-origin checks. Sign-in/signup and refresh are intentional authentication-bootstrap exceptions: they require JSON, enforce origin and Fetch Metadata checks, and do not authorize engine actions. Refresh uses an HttpOnly, SameSite=Strict cookie, Secure on HTTPS. The access token is tab-scoped in sessionStorage; no password or refresh token is stored there. Sign-out calls Supabase's local-session logout and clears the cookie. An invalidated/expired session is rejected by the SQL identity helper even while the old JWT is otherwise unexpired.

New audit/change/runtime records written inside authenticated control requests include an `actor` object (verified user ID and current role), captured before INSERT. Approvals record the verified account UUID, ignoring browser-supplied approver names. Public audit views display pseudonymous account IDs rather than exposing account emails. Admins can resolve IDs through the protected account list. Public polling deadline processing and CLI events remain system events without fabricated user identities. Audit triggers, policy ordering, grants, executor, kill switch, approvals, rate limits, breaker and verifier files are unchanged; hashes are protected in `docs/auth-engine-baseline.json`.

A public key does not grant access to engine tables. The private role-change history deliberately has RLS enabled without client policies/grants: direct table access is denied, yielding an informational Security Advisor notice. Only the checked admin function can append it. Never expose the private schemas through the Data API.

## Verification and limitations

139 pytest tests pass, including all 112 prior tests. Added tests cover guest/viewer refusal, operator/approver separation, no shared-token fallback, fresh demotion/logout rejection, provider outage, origin checks, signup metadata stripping, HttpOnly/Secure refresh cookie, audit attribution and unchanged engine hashes. Existing demo, dry-run, HTTP smoke and JS syntax checks pass.

Live transactional SQL probes (`scripts/verify_accounts.sql`) verified viewer defaults, forged metadata rejection, admin authorization, fresh role changes, logout rejection and the role audit. Probe users, sessions, grants and audit rows were rolled back; no test accounts remain. Anonymous/forged JWT RPC HTTP calls returned 401. Desktop/mobile browser checks used a mocked Auth provider to exercise sign-in, viewer control refusal, sign-out, admin login and role list rendering, with no page errors or overflow. Real-user email delivery and password sign-in still require the private project setup above and the owner's first account; no SMTP credentials were supplied or inferred.

The remediation database is still SQLite and remains ephemeral on the current free Render deployment. Supabase identity and role history persist separately. Password recovery UI, OAuth, MFA, account deletion UI and multi-tenant data isolation are not included. Public synthetic read-only views remain public, as before. This is a simulation, not production infrastructure remediation.
