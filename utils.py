# utils.py
from sqlalchemy.orm import joinedload
from models import db, User, Team
from datetime import datetime

def apply_uptime_scoring():
    # Load users with their team's service_statuses
    users = User.query.options(
        joinedload(User.team).joinedload(Team.service_statuses)
    ).filter_by(is_admin=False).all()

    for user in users:
        if not user.team:
            continue

        statuses = user.team.service_statuses or []
        up_count = sum(1 for s in statuses if s.status)
        down_count = sum(1 for s in statuses if not s.status)

        # Append scores safely
        user.uptime = (user.uptime or 0) + up_count * 10
        user.penalties = (user.penalties or 0) + down_count * 5
        user.update_total_score()

    db.session.commit()
    print(f"[{datetime.now()}] ✅ Uptime/downtime points appended.")
