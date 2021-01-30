import requests
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from admin.celery import app
from admin.models import Metric, Repo
from admin.settings import SANIC_CONFIG

engine = create_engine(
    f"postgres://{ SANIC_CONFIG['DB_USER'] }:{ SANIC_CONFIG['DB_PASSWORD'] }"
    f"@{ SANIC_CONFIG['DB_HOST'] }/{ SANIC_CONFIG['DB_DATABASE'] }"
)
Session = sessionmaker(bind=engine, autocommit=True)
session = Session()


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

    session.execute(Metric.__table__.insert(), metrics)
