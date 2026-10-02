# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class Team(db.Model):
    __tablename__ = "team"
    id   = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)

    users = db.relationship(
        "User",
        back_populates="team",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    # NOTE: this is the correct name used by ServiceStatus.team relationship
    service_statuses = db.relationship(
        "ServiceStatus",
        back_populates="team",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String, unique=True, nullable=False)
    team_name  = db.Column(db.String, unique=True, nullable=False)
    password   = db.Column(db.String, nullable=False)

    # bring these back because app.py uses them
    email_list = db.Column(db.String, nullable=True, default="")
    team_size  = db.Column(db.Integer, nullable=False, default=1)

    # scores the app uses elsewhere
    is_admin      = db.Column(db.Boolean, nullable=False, default=False)
    total         = db.Column(db.Integer, nullable=False, default=0)
    uptime        = db.Column(db.Integer, nullable=False, default=0)
    injects       = db.Column(db.Integer, nullable=False, default=0)
    web           = db.Column(db.Integer, nullable=False, default=0)
    image_scores  = db.Column(db.Integer, nullable=False, default=0)
    penalties     = db.Column(db.Integer, nullable=False, default=0)

    team_id = db.Column(
        db.Integer,
        db.ForeignKey("team.id", ondelete="SET NULL"),  # keep user if team is removed
        nullable=True,
    )
    team = db.relationship("Team", back_populates="users")

    def update_total_score(self):
        self.total = self.injects + self.web + self.uptime + self.image_scores - self.penalties

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    file_link = db.Column(db.String(200), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Inject(db.Model):
    __tablename__ = "inject"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), default="Offline")
    file_link = db.Column(db.String(200), nullable=True)
    countdown_minutes = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class WebChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), default="Not Started")
    file_link = db.Column(db.String(200), nullable=True)
    score = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class WebSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    challenge_id = db.Column(db.Integer, db.ForeignKey('web_challenge.id'))
    submitted_flag = db.Column(db.Text, nullable=True)
    submitted_file = db.Column(db.String(200), nullable=True)
    score_awarded = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='web_submissions')
    challenge = db.relationship('WebChallenge', backref='submissions')

class Service(db.Model):
    __tablename__ = "service"
    id   = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)

class ServiceStatus(db.Model):
    __tablename__ = "service_status"
    id         = db.Column(db.Integer, primary_key=True)
    team_id    = db.Column(db.Integer, db.ForeignKey("team.id", ondelete="CASCADE"), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey("service.id", ondelete="CASCADE"), nullable=False)
    status     = db.Column(db.Boolean, default=False, nullable=False)

    team    = db.relationship("Team", back_populates="service_statuses")
    service = db.relationship("Service")

# --- Image scoring history (time series) --------------------------------------
class VMImage(db.Model):
    __tablename__ = "vm_image"
    id   = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)

class ImageScoreEvent(db.Model):
    __tablename__ = "image_score_event"
    id        = db.Column(db.Integer, primary_key=True)
    team_id   = db.Column(db.Integer, db.ForeignKey("team.id", ondelete="CASCADE"), nullable=False)
    image_id  = db.Column(db.Integer, db.ForeignKey("vm_image.id", ondelete="CASCADE"), nullable=False)
    delta     = db.Column(db.Integer, nullable=False)  # +points or -penalties
    reason    = db.Column(db.String, nullable=True)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    team  = db.relationship("Team")
    image = db.relationship("VMImage")

    __table_args__ = (
        db.Index("ix_team_image_time", "team_id", "image_id", "timestamp"),
    )
