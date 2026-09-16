from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    database_url: str
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # Flags de la cookie de sesión: Secure=true exige HTTPS en producción
    cookie_secure: bool = True
    cookie_samesite: str = "lax"

    # Clave para firmar tokens CSRF (doble envío). Si no se define, reutiliza jwt_secret
    csrf_secret_key: str | None = None


settings = Settings()