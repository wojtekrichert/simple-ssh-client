import logging
from contextlib import contextmanager

import paramiko
from paramiko.client import SSHClient as ParamikoSSHClient
from paramiko.ssh_exception import NoValidConnectionsError
from retry.api import retry_call

from schema import ConnectionSettings

logger = logging.getLogger(__package__)


class SshConnectionException(Exception):
    """
    Exception related to error regarding
    connecting to host.
    """


class SshExecutionException(Exception):
    """
    Exception related to error regarding
    execution of commands.
    """

    def __init__(self, message, error_message, exit_status):
        message = (
            f"{message} Exit status: {exit_status}. "
            f"Error message:\n'{error_message}'"
        )
        super().__init__(message)
        self.error_message = error_message
        self.exit_status = exit_status


class SSHClient:
    CONNECTION_RETRIES = 3
    DEFAULT_TIMEOUT = 60

    def __init__(self, *, settings: ConnectionSettings, encoding: str = "UTF-8"):
        self.settings = settings
        self.encoding = encoding

    @staticmethod
    def __catch_error(stderr, exit_status):
        if exit_status != 0:
            error_lines = "\n".join([line.rstrip() for line in stderr.readlines()])
            error_message = error_lines if error_lines else ""
            raise SshExecutionException(
                message="Error occurred during execution.",
                error_message=error_message,
                exit_status=exit_status,
            )

    def __prepare_credentials(self):
        auth = {
            "hostname": str(self.settings.hostname),
            "username": self.settings.username,
        }
        if self.settings.private_key and self.settings.password:
            logger.warning(
                f"Private key and password provided "
                f"for host {self.settings.hostname}. "
                f"Private key will be used."
            )
        if self.settings.private_key:
            auth["pkey"] = self.settings.private_key.get_secret_value()
        else:
            auth["password"] = self.settings.password.get_secret_value()
        return auth

    @contextmanager
    def connect(self):
        """
        Context manager responsible for opening and closing
        connection to given host.
        Favours using private key instead of password.
        connection to host.
        Example usage:
        with self._connect() as client:
            <do something with client>
        :raises SshConnectionException: If lack of data for connecting to host
        :raises TimeoutError: host is unreachable, tried 3 times
        """
        ssh = ParamikoSSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            retry_call(
                ssh.connect,
                fkwargs=self.__prepare_credentials(),
                exceptions=(TimeoutError, NoValidConnectionsError),
                tries=self.CONNECTION_RETRIES,
                logger=None,
            )
            yield ssh
        finally:
            ssh.close()

    def execute(self, *, command: str, timeout: int = None) -> str:
        """
        Execute command on host.
        :param str command: bash command to be executed
        :param int timeout: timout in seconds
        :return str: execution output
        :raises SshExecutionException: if command execution fails
        (nonzero exit status, error lines)
        """
        logger.info(f"Executing command: '{command}' with timeout {timeout}s")
        with self.connect() as client:
            timeout = timeout if timeout is not None else self.DEFAULT_TIMEOUT
            _, stdout, stderr = client.exec_command(command, timeout=timeout)
            exit_status = stdout.channel.recv_exit_status()
            self.__catch_error(stderr=stderr, exit_status=exit_status)
            return stdout.read().decode(encoding=self.encoding)
