# My Account backend

## Stripe Identity

The backend creates Stripe Identity VerificationSessions only for the authenticated Supabase user. The browser receives only the transient VerificationSession client secret needed by Stripe.js, never `STRIPE_SECRET_KEY`, and never stores that client secret.

Identity state is stored in the user's Supabase metadata under `identity_verification`, limited to:

- `session_id`
- `status`
- `created_at`
- `completed_at`
- `last_updated_at`

Documents, images, biometric data, verification reports, and client secrets are not stored or logged.

Required backend variables are listed in `.env.example`. Set `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` only in the backend deployment environment. `STRIPE_PUBLISHABLE_KEY` is safe to return to the authenticated frontend, but it must also come from the environment.

Configure a Stripe webhook endpoint at:

`https://auth.lukintosh.com/api/webhooks/stripe/identity`

Subscribe it to these Identity events:

- `identity.verification_session.processing`
- `identity.verification_session.verified`
- `identity.verification_session.canceled`
- `identity.verification_session.requires_input`

The endpoint verifies the `Stripe-Signature` header, fetches the session from Stripe, and rejects events whose session ID is not already linked to the user. The authenticated status endpoint also rechecks Stripe, so a browser redirect is never treated as proof of verification.
