import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


@dataclass(frozen=True)
class Settings:
    supabase_url: str
    supabase_key: str
    supabase_anon_key: str
    database_url: str
    table_name: str = "transactions"


settings = Settings(
    supabase_url=os.getenv("SUPABASE_URL", ""),
    supabase_key=os.getenv("SUPABASE_KEY", os.getenv("SUPABASE_ANON_KEY", "")),
    supabase_anon_key=os.getenv("SUPABASE_ANON_KEY", os.getenv("SUPABASE_KEY", "")),
    database_url=os.getenv("DATABASE_URL", ""),
    table_name=os.getenv("TABLE_NAME", "transactions"),
)


def validate_settings() -> None:
    missing = []

    if not settings.supabase_url:
        missing.append("SUPABASE_URL")
    if not settings.supabase_key:
        missing.append("SUPABASE_KEY (or SUPABASE_ANON_KEY)")
    if not settings.database_url:
        missing.append("DATABASE_URL")

    if missing:
        missing_csv = ", ".join(missing)
        raise RuntimeError(f"Missing required environment variables: {missing_csv}")
