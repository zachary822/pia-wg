from typing import Optional
from pydantic import BaseSettings, SecretStr


class Settings(BaseSettings):
    PIA_USERNAME: str
    PIA_PASSWD: SecretStr

    class Config:
        env_file = ".env"
