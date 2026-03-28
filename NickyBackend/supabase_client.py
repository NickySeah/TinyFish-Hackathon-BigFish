from supabase import Client, create_client
from supabase.lib.client_options import ClientOptions

from config import settings


def get_anon_client() -> Client:
    return create_client(settings.supabase_url, settings.supabase_key)


def get_authenticated_client(access_token: str) -> Client:
    options = ClientOptions(headers={"Authorization": f"Bearer {access_token}"})
    return create_client(settings.supabase_url, settings.supabase_key, options=options)
