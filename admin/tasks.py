import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from admin.app import jinja
from admin.celery import app
from admin.models import Metric, Repo
from admin.settings import EMAIL_CONFIG, SANIC_CONFIG

engine = create_engine(
    f"postgresql://{ SANIC_CONFIG['DB_USER'] }:{ SANIC_CONFIG['DB_PASSWORD'] }"
    f"@{ SANIC_CONFIG['DB_HOST'] }/{ SANIC_CONFIG['DB_DATABASE'] }"
)
Session = sessionmaker(bind=engine)
session = Session()


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
        datetime=datetime.utcnow().strftime("%B %-d, %Y at %H:%M"),
    )

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    s = smtplib.SMTP(EMAIL_CONFIG["host"], EMAIL_CONFIG["port"])

    s.login(EMAIL_CONFIG["host_user"], EMAIL_CONFIG["host_password"])
    s.sendmail(msg["From"], msg["To"], msg.as_string())
    s.quit()


@app.task()
def check_sites():
    repos = session.query(Repo.__table__).all()
    metrics = []
    for repo in repos:
        if repo.url:
            response = requests.get(repo.url)
            metrics.append(
                {
                    "site": repo.id,
                    "response_time": response.elapsed,
                    "response_size": round(len(response.content) / 1024, 3),
                    "status_code": response.status_code,
                }
            )

            if response.status_code != 200:
                send_email(repo)

    session.execute(Metric.__table__.insert(), metrics)
    session.commit()
