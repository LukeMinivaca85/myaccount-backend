# My Account backend

## Didit Identity

The backend creates Didit verification sessions only for the authenticated Supabase user. The browser receives only the temporary Didit hosted session URL, never the Didit API key or webhook secret, and the application does not store images, documents, videos, or biometric data.

Identity state is stored in the user's Supabase metadata under `identity_verification`, limited to:

- `session_id`
- `status`
- `created_at`
- `completed_at`
- `last_updated_at`

Documents, images, biometric data, verification reports, and client secrets are not stored or logged.

Required backend variables are listed in `.env.example`. Set `DIDIT_API_KEY`, `DIDIT_FACE_WORKFLOW_ID`, `DIDIT_DOCUMENT_WORKFLOW_ID`, `DIDIT_AGE_WORKFLOW_ID`, `DIDIT_ADAPTIVE_AGE_WORKFLOW_ID` and `DIDIT_WEBHOOK_SECRET` only in the backend deployment environment. `DIDIT_BASE_URL` should remain `https://verification.didit.me` unless Didit provides another endpoint for the account.

Age endpoints use separate Didit workflows:

- `POST /api/identity/start-age` for selfie-based age estimation.
- `POST /api/identity/start-adaptive-age` for adaptive age estimation with Didit's configured document fallback.
- `GET /api/identity/status?type=age` and `GET /api/identity/status?type=adaptive_age` for authenticated status checks.

The backend does not store the estimated age, confidence score, images, documents, or biometric data. It stores only the workflow type, session ID, status, and timestamps.

Configure a Didit webhook endpoint at:

`https://auth.lukintosh.com/api/webhooks/didit/identity`

Subscribe it to these Identity events:

- `identity.verification_session.processing`
- `identity.verification_session.verified`
- `identity.verification_session.canceled`
- `identity.verification_session.requires_input`

The endpoint verifies `X-Signature-V2` and `X-Timestamp`, rejects events whose session ID is not already linked to the authenticated user, and stores only the provider, session ID, status, and timestamps. The authenticated status endpoint also rechecks Didit, so a browser callback is never treated as proof of verification.
