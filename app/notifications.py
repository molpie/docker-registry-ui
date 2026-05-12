import logging
import smtplib
from email.mime.text import MIMEText

import requests

from .config import Config

logger = logging.getLogger(__name__)


def _build_recap_text(registry_name, scan_result):
    scanned = scan_result.get("scanned", 0)
    skipped = scan_result.get("skipped", 0)
    errors = scan_result.get("errors", 0)
    dry_run = scan_result.get("dryRun", False)
    mode = "DRY RUN" if dry_run else "EXECUTED"
    return (
        f"Massive scan recap ({mode})\n"
        f"Registry: {registry_name}\n"
        f"Scanned: {scanned}\n"
        f"Skipped: {skipped}\n"
        f"Errors: {errors}\n"
    )


def send_email_recap(registry_name, scan_result):
    if not Config.NOTIFY_EMAIL_ENABLED:
        return False

    missing = [
        key
        for key in ["NOTIFY_EMAIL_SMTP_HOST", "NOTIFY_EMAIL_TO", "NOTIFY_EMAIL_FROM"]
        if not getattr(Config, key)
    ]
    if missing:
        logger.warning(f"Email recap disabled due to missing config: {', '.join(missing)}")
        return False

    body = _build_recap_text(registry_name, scan_result)
    msg = MIMEText(body)
    msg["Subject"] = f"[Registry UI] Massive scan recap - {registry_name}"
    msg["From"] = Config.NOTIFY_EMAIL_FROM
    msg["To"] = Config.NOTIFY_EMAIL_TO

    try:
        with smtplib.SMTP(Config.NOTIFY_EMAIL_SMTP_HOST, Config.NOTIFY_EMAIL_SMTP_PORT, timeout=20) as server:
            if Config.NOTIFY_EMAIL_USE_TLS:
                server.starttls()
            if Config.NOTIFY_EMAIL_SMTP_USER:
                server.login(Config.NOTIFY_EMAIL_SMTP_USER, Config.NOTIFY_EMAIL_SMTP_PASSWORD or "")
            server.sendmail(Config.NOTIFY_EMAIL_FROM, [Config.NOTIFY_EMAIL_TO], msg.as_string())
        logger.info(f"Massive scan email recap sent for {registry_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email recap for {registry_name}: {e}")
        return False


def send_telegram_recap(registry_name, scan_result):
    if not Config.NOTIFY_TELEGRAM_ENABLED:
        return False
    if not Config.NOTIFY_TELEGRAM_BOT_TOKEN or not Config.NOTIFY_TELEGRAM_CHAT_ID:
        logger.warning("Telegram recap disabled due to missing token/chat id")
        return False

    body = _build_recap_text(registry_name, scan_result)
    url = f"https://api.telegram.org/bot{Config.NOTIFY_TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": Config.NOTIFY_TELEGRAM_CHAT_ID,
        "text": body,
    }

    try:
        response = requests.post(url, json=payload, timeout=15)
        if response.status_code >= 300:
            logger.error(
                f"Failed to send Telegram recap for {registry_name}: HTTP {response.status_code}"
            )
            return False
        logger.info(f"Massive scan Telegram recap sent for {registry_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to send Telegram recap for {registry_name}: {e}")
        return False


def send_massive_scan_recap(registry_name, scan_result):
    email_ok = send_email_recap(registry_name, scan_result)
    telegram_ok = send_telegram_recap(registry_name, scan_result)
    return {"email": email_ok, "telegram": telegram_ok}
