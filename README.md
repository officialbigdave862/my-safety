# Guardian Security — Render-ready starter

A consent-based personal device security dashboard. Includes account registration/login, device registration, user-triggered browser geolocation, security event history, and a user-triggered front-camera photo preview/download.

## Deploy on Render
1. Create a GitHub repository and upload the contents of this ZIP.
2. In Render, choose **New + → Blueprint** and select the repository (it reads `render.yaml`), or create a Python web service with build command `pip install -r requirements.txt` and start command `gunicorn app:app`.
3. Ensure `SECRET_KEY` is set to a long random secret. The Blueprint generates one automatically.
4. Deploy. Use HTTPS; browser geolocation and camera permissions require a secure context.

## Important deployment note
This starter uses SQLite in the app directory for simplicity. On Render, the filesystem of a typical web service is ephemeral, and local database contents can be lost on redeploy/restart. For persistent production data, configure a Render persistent disk and set `DATABASE_PATH` to a file on that disk, or migrate to Render PostgreSQL before real use. SQLite is not suitable for multiple web instances.

## Current capabilities / limits
- Users can register and sign in.
- Users can register their own device, then explicitly request its current browser location.
- Location updates are shown on the dashboard and map link.
- Camera access requires browser permission and only takes a photo after the user presses **Capture photo**. The image stays in the browser until the user downloads it.
- Security events are recorded in a log.
- This web app cannot monitor activity in other phone apps, secretly record the screen, or guarantee background tracking. A native Android app and explicit permissions are needed for additional device-level features.

## Security checklist before production
- Add CSRF protection and rate limiting.
- Configure persistent storage/PostgreSQL and backups.
- Add email verification, password reset, and stronger session policy.
- Add HTTPS-only secure cookie settings once deployed.
- Review applicable privacy/data protection law and provide a clear consent/retention policy.
- Do not use this app to monitor people or devices without authorization.
