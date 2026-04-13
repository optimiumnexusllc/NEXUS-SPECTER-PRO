"""
NEXUS SPECTER PRO — Alert Engine
Multi-channel notifications: Slack · Microsoft Teams · Email (SMTP) · Webhook
Sends alerts on: critical findings, mission completion, risk regression, new assets.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import os, json, logging, smtplib
from dataclasses import dataclass, field
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from rich.console import Console

console = Console()
log = logging.getLogger("nsp.automation.alerts")

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


ALERT_LEVELS = {
    "critical": {"color": "#FF003C", "emoji": "🔴", "slack_color": "danger"},
    "error":    {"color": "#FF003C", "emoji": "❌", "slack_color": "danger"},
    "warning":  {"color": "#FF8C00", "emoji": "⚠️",  "slack_color": "warning"},
    "info":     {"color": "#00FFD4", "emoji": "✅", "slack_color": "good"},
    "success":  {"color": "#00FFD4", "emoji": "🎉", "slack_color": "good"},
}


@dataclass
class AlertConfig:
    # Slack
    slack_webhook:     str  = ""
    slack_channel:     str  = "#nsp-alerts"
    # Teams
    teams_webhook:     str  = ""
    # Email
    smtp_host:         str  = ""
    smtp_port:         int  = 587
    smtp_user:         str  = ""
    smtp_pass:         str  = ""
    smtp_from:         str  = "nsp@optimiumnexus.com"
    smtp_to:           list = field(default_factory=list)
    # Generic webhook
    webhook_url:       str  = ""
    webhook_headers:   dict = field(default_factory=dict)
    # Filters
    min_level:         str  = "warning"   # only send warning+ by default
    enabled:           bool = True


@dataclass
class SentAlert:
    alert_id:   str
    title:      str
    message:    str
    level:      str
    channels:   list
    sent_at:    str
    success:    bool


class AlertEngine:
    """
    Multi-channel alert engine for NEXUS SPECTER PRO.
    Sends structured notifications to Slack, Teams, Email, and generic webhooks.
    Supports rate limiting and minimum level filtering.
    """

    LEVEL_ORDER = {"info":0,"success":0,"warning":1,"error":2,"critical":3}

    def __init__(self, config: AlertConfig = None):
        self.config = config or AlertConfig(
            slack_webhook  = os.getenv("SLACK_WEBHOOK_URL",""),
            teams_webhook  = os.getenv("TEAMS_WEBHOOK_URL",""),
            smtp_host      = os.getenv("SMTP_HOST",""),
            smtp_port      = int(os.getenv("SMTP_PORT","587")),
            smtp_user      = os.getenv("SMTP_USER",""),
            smtp_pass      = os.getenv("SMTP_PASS",""),
            smtp_to        = os.getenv("ALERT_EMAIL","").split(","),
            webhook_url    = os.getenv("NSP_WEBHOOK_URL",""),
        )
        self._sent_count = 0

    def _should_send(self, level: str) -> bool:
        if not self.config.enabled:
            return False
        min_rank = self.LEVEL_ORDER.get(self.config.min_level, 0)
        cur_rank = self.LEVEL_ORDER.get(level, 0)
        return cur_rank >= min_rank

    # ── Slack ─────────────────────────────────────────────────────────────────
    def _send_slack(self, title: str, message: str, level: str,
                     fields: list = None) -> bool:
        if not self.config.slack_webhook or not REQUESTS_OK:
            return False
        meta = ALERT_LEVELS.get(level, ALERT_LEVELS["info"])
        payload = {
            "channel":     self.config.slack_channel,
            "username":    "NEXUS SPECTER PRO",
            "icon_emoji":  ":ghost:",
            "attachments": [{
                "color":      meta["slack_color"],
                "title":      f"{meta['emoji']} {title}",
                "text":       message,
                "footer":     "NEXUS SPECTER PRO | OPTIMIUM NEXUS LLC",
                "footer_icon":"",
                "ts":         int(datetime.utcnow().timestamp()),
                "fields":     fields or [],
            }],
        }
        try:
            r = requests.post(self.config.slack_webhook,
                              json=payload, timeout=10)
            if r.status_code == 200:
                log.info(f"[ALERT][SLACK] Sent: {title}")
                return True
            log.warning(f"[ALERT][SLACK] HTTP {r.status_code}")
        except Exception as e:
            log.error(f"[ALERT][SLACK] Error: {e}")
        return False

    # ── Microsoft Teams ────────────────────────────────────────────────────────
    def _send_teams(self, title: str, message: str, level: str) -> bool:
        if not self.config.teams_webhook or not REQUESTS_OK:
            return False
        meta   = ALERT_LEVELS.get(level, ALERT_LEVELS["info"])
        color  = meta["color"].replace("#","")
        payload = {
            "@type":    "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": color,
            "summary":    title,
            "sections": [{
                "activityTitle":    f"{meta['emoji']} **{title}**",
                "activitySubtitle": "NEXUS SPECTER PRO | OPTIMIUM NEXUS LLC",
                "activityText":     message,
                "facts": [
                    {"name":"Platform","value":"NEXUS SPECTER PRO"},
                    {"name":"Company","value":"OPTIMIUM NEXUS LLC"},
                    {"name":"Time","value":datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")},
                ],
            }],
        }
        try:
            r = requests.post(self.config.teams_webhook,
                              json=payload, timeout=10)
            if r.status_code in (200, 202):
                log.info(f"[ALERT][TEAMS] Sent: {title}")
                return True
        except Exception as e:
            log.error(f"[ALERT][TEAMS] Error: {e}")
        return False

    # ── Email ─────────────────────────────────────────────────────────────────
    def _send_email(self, title: str, message: str, level: str) -> bool:
        if not self.config.smtp_host or not self.config.smtp_to:
            return False
        recipients = [r for r in self.config.smtp_to if r.strip()]
        if not recipients:
            return False
        meta = ALERT_LEVELS.get(level, ALERT_LEVELS["info"])
        msg  = MIMEMultipart("alternative")
        msg["Subject"] = f"[NSP] {meta['emoji']} {title}"
        msg["From"]    = self.config.smtp_from
        msg["To"]      = ", ".join(recipients)

        html_body = f"""
<html><body style="background:#0A0A0A;color:#E8E8E8;font-family:monospace;padding:24px;">
  <div style="border-left:4px solid {meta['color']};padding-left:16px;">
    <h2 style="color:{meta['color']};">{meta['emoji']} {title}</h2>
    <pre style="background:#111;padding:16px;border-radius:6px;white-space:pre-wrap;">
{message}
    </pre>
    <hr style="border-color:#1E1E1E;">
    <p style="color:#555;font-size:11px;">
      NEXUS SPECTER PRO | OPTIMIUM NEXUS LLC<br>
      contact@optimiumnexus.com | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
    </p>
  </div>
</body></html>"""

        msg.attach(MIMEText(message, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
                server.ehlo()
                server.starttls()
                if self.config.smtp_user and self.config.smtp_pass:
                    server.login(self.config.smtp_user, self.config.smtp_pass)
                server.sendmail(self.config.smtp_from, recipients, msg.as_string())
            log.info(f"[ALERT][EMAIL] Sent to {recipients}: {title}")
            return True
        except Exception as e:
            log.error(f"[ALERT][EMAIL] Error: {e}")
        return False

    # ── Generic Webhook ────────────────────────────────────────────────────────
    def _send_webhook(self, title: str, message: str, level: str,
                       extra: dict = None) -> bool:
        if not self.config.webhook_url or not REQUESTS_OK:
            return False
        payload = {
            "platform":  "NEXUS SPECTER PRO",
            "company":   "OPTIMIUM NEXUS LLC",
            "title":     title,
            "message":   message,
            "level":     level,
            "timestamp": datetime.utcnow().isoformat(),
            **(extra or {}),
        }
        try:
            r = requests.post(
                self.config.webhook_url,
                json    = payload,
                headers = {**{"Content-Type":"application/json"},
                           **self.config.webhook_headers},
                timeout = 10,
            )
            if r.status_code < 300:
                log.info(f"[ALERT][WEBHOOK] Sent: {title}")
                return True
        except Exception as e:
            log.error(f"[ALERT][WEBHOOK] Error: {e}")
        return False

    # ── Main send ─────────────────────────────────────────────────────────────
    def send(
        self,
        title:   str,
        message: str,
        level:   str = "info",
        fields:  list = None,
        extra:   dict = None,
    ) -> SentAlert:
        if not self._should_send(level):
            log.debug(f"[ALERT] Suppressed (below min level '{self.config.min_level}'): {title}")
            return SentAlert("","",message,level,[],datetime.utcnow().isoformat(),False)

        meta     = ALERT_LEVELS.get(level, ALERT_LEVELS["info"])
        channels = []

        if self._send_slack(title, message, level, fields):   channels.append("slack")
        if self._send_teams(title, message, level):           channels.append("teams")
        if self._send_email(title, message, level):           channels.append("email")
        if self._send_webhook(title, message, level, extra):  channels.append("webhook")

        if not channels:
            console.print(f"  [dim][ALERT] {meta['emoji']} {title} — {message[:60]}[/dim]")

        self._sent_count += 1
        alert = SentAlert(
            alert_id  = f"NSP-ALERT-{self._sent_count:04d}",
            title     = title,
            message   = message,
            level     = level,
            channels  = channels,
            sent_at   = datetime.utcnow().isoformat(),
            success   = len(channels) > 0,
        )
        log.info(f"[ALERT] Sent '{title}' via: {channels or ['console']}")
        return alert

    # ── Shortcut helpers ──────────────────────────────────────────────────────
    def critical(self, title: str, message: str, **kw) -> SentAlert:
        return self.send(title, message, "critical", **kw)

    def warn(self, title: str, message: str, **kw) -> SentAlert:
        return self.send(title, message, "warning", **kw)

    def info(self, title: str, message: str, **kw) -> SentAlert:
        return self.send(title, message, "info", **kw)

    def mission_complete(self, target: str, session_id: str,
                          findings_summary: dict) -> SentAlert:
        """Structured alert for mission completion."""
        crit = findings_summary.get("critical", 0)
        high = findings_summary.get("high", 0)
        total= sum(findings_summary.values())
        level = "critical" if crit > 0 else "warning" if high > 0 else "info"
        return self.send(
            title   = f"Mission Complete: {target}",
            message = (f"Session: {session_id}\n"
                       f"Findings: {total} total | {crit} critical | {high} high\n"
                       f"Action required: {'YES — CRITICAL FINDINGS' if crit > 0 else 'Review high-severity findings'}"),
            level   = level,
            fields  = [
                {"title": "Target",      "value": target,        "short": True},
                {"title": "Critical",    "value": str(crit),     "short": True},
                {"title": "High",        "value": str(high),     "short": True},
                {"title": "Total",       "value": str(total),    "short": True},
            ],
        )
