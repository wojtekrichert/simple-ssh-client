from unittest import mock
from unittest.mock import MagicMock

import factory
import pytest
from paramiko.ssh_exception import NoValidConnectionsError
from pydantic import SecretStr

from simple_ssh_client.client import SSHClient, SshExecutionException
from simple_ssh_client.schema import ConnectionSettings


class ConnectionSettingsFactory(factory.Factory):
    class Meta:
        model = ConnectionSettings

    hostname = factory.Faker("ipv4")
    username = factory.Faker("word")
    password = factory.Faker("word")


@pytest.fixture()
def ssh_client():
    return SSHClient(settings=ConnectionSettingsFactory())


class TestSSHClient:
    def test___catch_error(self, ssh_client):
        ssh_client._SSHClient__catch_error(stderr="blank", exit_status=0)

        stderr = MagicMock()
        stderr.readlines.return_value = ["first", "second", "third"]
        with pytest.raises(SshExecutionException) as error:
            ssh_client._SSHClient__catch_error(stderr=stderr, exit_status=1)
        stderr.readlines.assert_called_once()
        assert "\n".join(stderr.readlines.return_value) in error.exconly()
        assert "Exit status: 1" in error.exconly()

    def test___prepare_credentials(self, ssh_client):
        auth = ssh_client._SSHClient__prepare_credentials()
        assert auth == {
            "hostname": str(ssh_client.settings.hostname),
            "username": ssh_client.settings.username,
            "password": ssh_client.settings.password.get_secret_value(),
        }

        ssh_client.settings.private_key = SecretStr("password")
        auth = ssh_client._SSHClient__prepare_credentials()
        assert auth == {
            "hostname": str(ssh_client.settings.hostname),
            "username": ssh_client.settings.username,
            "pkey": ssh_client.settings.private_key.get_secret_value(),
        }

    @mock.patch("simple_ssh_client.client.ParamikoSSHClient")
    @mock.patch("simple_ssh_client.client.paramiko.AutoAddPolicy", return_value="test")
    @mock.patch("simple_ssh_client.client.retry_call")
    @mock.patch(
        "simple_ssh_client.client.SSHClient._SSHClient__prepare_credentials",
        return_value="test",
    )
    def test_connect(self, _, retry_mock, policy_mock, paramiko_mock, ssh_client):
        ssh_mock = MagicMock()
        ssh_mock.set_missing_host_key_policy = MagicMock()
        ssh_mock.close = MagicMock()
        ssh_mock.connect = "test connect"
        paramiko_mock.return_value = ssh_mock

        with ssh_client.connect() as ssh:
            assert isinstance(ssh, type(ssh_mock))

        paramiko_mock.assert_called_once()
        ssh_mock.set_missing_host_key_policy.assert_called_once()
        ssh_mock.close.assert_called_once()
        policy_mock.assert_called_once()
        retry_mock.assert_called_once_with(
            ssh_mock.connect,
            fkwargs="test",
            exceptions=(TimeoutError, NoValidConnectionsError),
            tries=3,
            logger=None,
        )

    @mock.patch("simple_ssh_client.client.SSHClient.connect")
    def test_execute(self, connect_mock, ssh_client):
        stdout = MagicMock()
        stdout.channel.recv_exit_status = MagicMock(return_value=0)
        stdout.read = MagicMock(return_value=b"test")
        exec_mock = MagicMock(return_value=["stdin", stdout, "stderr"])
        connect_mock.return_value.__enter__.return_value.exec_command = exec_mock

        output = ssh_client.execute(command="test")
        exec_mock.assert_called_once_with("test", timeout=60)
        stdout.channel.recv_exit_status.assert_called_once()
        stdout.read.assert_called_once()
        assert output == "test"
