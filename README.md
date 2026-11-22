# GEO-DIAGNOSTIC PRO

A three-portal, consent-based device diagnostics web app.

## Features
- Admin portal: password-protected dashboard, create/revoke session links, QR generation.
- User portal: explicit consent, ten optional browser/device diagnostics.
- Results portal: timestamped submitted reports, session history, PDF export.
- Location is requested only after the visitor taps the location button.
- Camera and microphone are local-only tests. No media is recorded or uploaded.
- The user explicitly confirms before report submission.

## Important browser limitations
A website cannot reliably read every hardware detail. Mobile browsers intentionally restrict IMEI, phone number, serial number, MAC address, installed apps, precise network identifiers, and many sensor/battery APIs. This app does not attempt to bypass those protections. GPS and camera/microphone require HTTPS and browser permission. Availability varies by browser and device.

## Run locally
Python 3.10+ recommended.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux/Termux: source .venv/bin/activate
pip install -r requirements.txt
```

Create a password hash:
```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('Choose-A-Strong-Password'))"
```

Set environment variables (use your own values):
```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export ADMIN_USERNAME="your-admin-name"
export ADMIN_PASSWORD_HASH="paste-the-hash"
export DATABASE_URL="sqlite:///diagnostics.db"
export PUBLIC_BASE_URL="http://127.0.0.1:5000"
export COOKIE_SECURE="false"
python app.py
```
Open http://127.0.0.1:5000/admin/login

## Free public deployment (Render + managed PostgreSQL)
1. Create a private Git repository and upload these project files.
2. Create a managed PostgreSQL database with a free tier (availability/limits depend on provider and may change).
3. Create a Render Web Service from the repository. Render can use `render.yaml`.
4. Add environment variables in the Render dashboard:
   - `SECRET_KEY`: long random secret
   - `ADMIN_USERNAME`: your chosen admin username
   - `ADMIN_PASSWORD_HASH`: password hash generated above
   - `DATABASE_URL`: PostgreSQL connection string from your database provider
   - `PUBLIC_BASE_URL`: your deployed HTTPS URL, e.g. `https://your-app.onrender.com`
   - `COOKIE_SECURE`: `true`
5. Deploy. Visit `/admin/login`.

Free hosting caveats: free web services may sleep, have usage limits, and do not guarantee uptime. Do not use SQLite on an ephemeral free host for important data; connect a persistent managed PostgreSQL database. Check the host/database provider's current free-tier retention and limits before relying on it.

## Security and privacy checklist
- Use a strong, unique admin password and keep the password hash and SECRET_KEY private.
- Keep the repository private if it contains any environment files. Never commit `.env`.
- Use HTTPS for deployed diagnostic links.
- Create links only for people who know why they are receiving them.
- Do not request location/camera/microphone unless needed for the test.
- Do not ask users to share reports containing sensitive details unnecessarily.
- Delete records when no longer needed; configure database backups and retention yourself.
- This starter does not include enterprise-grade audit logging, CSRF tokens, CAPTCHA, or automated deletion. Add these before production use with real users.
