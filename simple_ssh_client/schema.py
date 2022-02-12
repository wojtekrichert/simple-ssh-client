from typing import Optional

from pydantic import (
    BaseModel,
    IPvAnyAddress,
    SecretStr,
    ValidationError,
    root_validator,
)


class ConnectionSettings(BaseModel):
    """
    Object containing all informations
    necessary to connect to host and execute commands.
    """

    hostname: IPvAnyAddress
    username: str
    password: Optional[SecretStr]
    private_key: Optional[SecretStr]
    port: Optional[int] = 22

    @root_validator(pre=True)
    def check_credentials(cls, values):  # pylint: disable=R0201,E0213
        """
        Check if any of private key or password
        were given in constructor.
        """
        private_key = values.get("private_key")
        password = values.get("password")
        if not private_key and not password:
            raise ValidationError("Password or private key required.")
        return values
