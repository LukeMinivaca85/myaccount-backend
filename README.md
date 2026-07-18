# My Account backend

## Veriff Identity

The backend creates Veriff verification sessions only for the authenticated Supabase user. The browser receives only the temporary Veriff session URL, never the Veriff API key or shared secret, and the application does not store images, documents, videos, or biometric data.

Identity state is stored in the user's Supabase metadata under `identity_verification`, limited to:

- `session_id`
- `status`
- `created_at`
- `completed_at`
- `last_updated_at`

Documents, images, biometric data, verification reports, and client secrets are not stored or logged.

Required backend variables are listed in `.env.example`. Set `VERIFF_API_KEY` and `VERIFF_SHARED_SECRET` only in the backend deployment environment. `VERIFF_BASE_URL` should point to the base URL provided for the Veriff integration.

Configure a Veriff webhook endpoint at:

`https://auth.lukintosh.com/api/webhooks/veriff/identity`

Subscribe it to these Identity events:

- `identity.verification_session.processing`
- `identity.verification_session.verified`
- `identity.verification_session.canceled`
- `identity.verification_session.requires_input`

The endpoint verifies `X-AUTH-CLIENT` and `X-HMAC-SIGNATURE`, rejects events whose session ID is not already linked to the authenticated user, and stores only the provider, session ID, status, and timestamps. The authenticated status endpoint also rechecks Veriff, so a browser callback is never treated as proof of verification.
