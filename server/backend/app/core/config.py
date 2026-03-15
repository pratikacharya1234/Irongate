"""IronGate — Application Configuration."""
from functools import lru_cache
from typing import List
from pydantic import field_validator
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "IronGate"
    APP_ENV: str = "production"
    APP_DEBUG: bool = False
    APP_VERSION: str = "2.0.0"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    APP_WORKERS: int = 4
    ALLOWED_ORIGINS: str = "http://localhost:3000"
    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_origins(cls, v): return v
    @property
    def cors_origins(self) -> List[str]: return [o.strip() for o in self.ALLOWED_ORIGINS.split(",")]
    SECRET_KEY: str = "CHANGE_ME"
    JWT_SECRET_KEY: str = "CHANGE_ME"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    API_KEY_HEADER: str = "X-API-Key"
    BCRYPT_ROUNDS: int = 12
    DATABASE_URL: str = "postgresql+asyncpg://irongate:changeme@localhost:5432/irongate"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10
    DATABASE_POOL_TIMEOUT: int = 30
    DATABASE_ECHO: bool = False
    @property
    def sync_database_url(self) -> str: return self.DATABASE_URL.replace("+asyncpg", "")
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: str = ""
    REDIS_MAX_CONNECTIONS: int = 50
    REDIS_CACHE_TTL: int = 300
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_AUTH: str = "20/minute"
    RATE_LIMIT_REGISTRATION: str = "5/minute"
    THREAT_CONFIDENCE_THRESHOLD: float = 0.75
    THREAT_AUTO_BAN_THRESHOLD: float = 0.95
    THREAT_MAX_VIOLATIONS_BEFORE_BAN: int = 5
    ANOMALY_DETECTION_WINDOW_HOURS: int = 24
    REQUEST_RATE_SPIKE_MULTIPLIER: float = 3.0
    BAN_PROPAGATION_WEBHOOK_TIMEOUT: int = 10
    BAN_PROPAGATION_MAX_RETRIES: int = 3
    BAN_PROPAGATION_RETRY_DELAY: int = 5
    TRUST_NETWORK_NODE_ID: str = "default-node"
    TRUST_NETWORK_SHARED_SECRET: str = "CHANGE_ME"
    TRUST_SCORE_DECAY_RATE: float = 0.01
    TRUST_SCORE_INITIAL: int = 50
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    LOG_FILE: str = "/var/log/irongate/app.log"
    AUDIT_LOG_FILE: str = "/var/log/irongate/audit.log"
    WEBHOOK_SECRET: str = "CHANGE_ME"
    SLACK_WEBHOOK_URL: str = ""
    PAGERDUTY_API_KEY: str = ""
    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "case_sensitive": True}

@lru_cache
def get_settings() -> Settings: return Settings()
