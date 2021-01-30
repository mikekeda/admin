from celery import Celery
from celery.schedules import crontab

app = Celery("admin")
app.config_from_object("admin.settings", namespace="CELERY")

app.autodiscover_tasks(["admin"])

app.conf.beat_schedule = {
    "every-hour": {
        "task": "admin.tasks.check_sites",
        "schedule": crontab(minute=0, hour="*/1"),
        "args": (),
    },
}
