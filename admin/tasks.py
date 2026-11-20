import smtplib
from datetime import datetime, UTC
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests
from celery.utils.log import get_task_logger
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from admin.app import jinja
from admin.celery import app
from admin.models import Metric, Repo
from admin.settings import EMAIL_CONFIG, SANIC_CONFIG

SITE_CHECK_TIMEOUT = 30

engine = create_engine(
    f"postgresql://{ SANIC_CONFIG['DB_USER'] }:{ SANIC_CONFIG['DB_PASSWORD'] }"
    f"@{ SANIC_CONFIG['DB_HOST'] }/{ SANIC_CONFIG['DB_DATABASE'] }",
    pool_pre_ping=True,
)
Session = sessionmaker(bind=engine)
logger = get_task_logger(__name__)


def send_email(site: Repo) -> None:
    """Send email alert for the giving site."""
    title = f"[ALERT] Failure of uptime check on {site.title}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = title
    msg["From"] = EMAIL_CONFIG["email"]
    msg["To"] = EMAIL_CONFIG["recipient"]

    text = title
    html = jinja.env.get_template("_email_alert.html").render(
        site=site,
        title=title,
        datetime=datetime.now(UTC).strftime("%B %-d, %Y at %H:%M"),
    )

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    s = smtplib.SMTP(EMAIL_CONFIG["host"], EMAIL_CONFIG["port"], timeout=SITE_CHECK_TIMEOUT)

    s.login(EMAIL_CONFIG["host_user"], EMAIL_CONFIG["host_password"])
    s.sendmail(msg["From"], msg["To"], msg.as_string())
    s.quit()


@app.task()
def check_sites():
    # A session per run: a long-lived one stays broken after a dropped connection and fails every later run.
    with Session() as session:
        repos = session.query(Repo.__table__).all()

    metrics = []
    down = []
    for repo in repos:
        if not repo.url:
            continue
        try:
            response = requests.get(repo.url, timeout=SITE_CHECK_TIMEOUT)
        except requests.RequestException as e:
            logger.warning("Uptime check failed for %s: %r", repo.title, e)
            down.append(repo)
            continue

        metrics.append(
            {
                "site": repo.id,
                "response_time": response.elapsed,
                "response_size": round(len(response.content) / 1024, 3),
                "status_code": response.status_code,
            }
        )
        if response.status_code != 200:
            down.append(repo)

    if metrics:
        with Session.begin() as session:
            session.execute(Metric.__table__.insert(), metrics)

    # Metrics are saved first and each alert is sent on its own, so one mail failure loses nothing else.
    for repo in down:
        try:
            send_email(repo)
        except (smtplib.SMTPException, OSError) as e:
            logger.error("Could not send the alert for %s: %r", repo.title, e)
