Send Email PHP Endpoint
=======================

This folder contains a lightweight PHP endpoint (`send-email.php`) that accepts a JSON POST and attempts to send an email using PHP's `mail()` function.

Usage (expected JSON payload):

{
  "to": "recipient@example.com",
  "subject": "Your temporary password",
  "text": "Plain text body",
  "html": "<p>HTML body</p>",
  "apiKey": "optional-shared-key"
}

Environment variables (set on Render):

- `PHP_MAIL_KEY` (optional) — secret that must match `apiKey` in the request
- `FROM_EMAIL` (optional) — value used in the From header

Deploying to Render.com
-----------------------

1. Create a new Git repository (or a subfolder) containing this `email_service` folder and push to GitHub.

2. On Render, create a new Web Service:
   - Connect your repo and pick the branch.
   - Set the `Root` (or `Build Command`) to the folder containing `send-email.php` if needed.
   - Set the `Start Command` to: `php -S 0.0.0.0:10000 -t .`
   - Add environment variables: `PHP_MAIL_KEY` (optional), `FROM_EMAIL` (optional).

3. Once deployed, the endpoint will be available at `https://<your-service>.onrender.com/send-email.php`.

Notes & recommendations
-----------------------
- `mail()` relies on the host's mail transport (sendmail/postfix). On many managed hosts this is available; on others you may need to implement SMTP or use an external API.
- For production reliability, consider using an external mail API (SendGrid, Mailgun) from the PHP service or configure SMTP and use PHPMailer.
- Keep `PHP_MAIL_KEY` secret and use HTTPS.
