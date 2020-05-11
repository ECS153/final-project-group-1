import logging
from pathlib import Path

from Crypto.PublicKey.RSA import _RSAobj, importKey
import requests
from requests.exceptions import ConnectionError


class Client:
    def __init__(self, server_url: str, user_name: str, password: str,
                 logger_name=None):
        """
        Creates a new client which can communicate with a server.

        Args:
        server_url: The server's url. Example: 'https://server.com'
        user_name: The user's user name.
        password: The user's password.
        logger_name: The name of the logger to use.
        """
        self._logger = logging.getLogger(logger_name)
        self._password = password
        self._server_url = server_url
        self._user_name = user_name

    @property
    def keys_path(self) -> Path:
        return Path(__file__).parent / 'keys'

    @property
    def password(self) -> str:
        return self._password

    @password.setter
    def password(self, password: str):
        self._password = password

    @property
    def server_url(self) -> str:
        return self._server_url

    @server_url.setter
    def server_url(self, url: str):
        self._server_url = url

    @property
    def user_name(self) -> str:
        return self._user_name

    @user_name.setter
    def user_name(self, user_name: str):
        self._user_name = user_name

    def _decrypt(self, message: bytes) -> bytes:
        """
        Decrypts a message with the user's decryption key.
        """
        key = self._get_decryption_key()
        decrypted = key.decrypt(message)
        return decrypted

    def _encrypt(self, message: bytes, receiver: str) -> bytes:
        """
        Encrypts a message with the receiver's encryption key.

        Args:
        message: The message to encrypt.
        receiver: The message recipient's user name.
        """
        key = self._get_encryption_key(receiver)
        encrypted, = key.encrypt(message, None)
        return encrypted

    def _get_decryption_key(self) -> _RSAobj:
        """
        Gets the user's decryption key.
        """
        key_file_path = self.keys_path / 'private_{}.pem'.format(
                self.user_name)
        return self._get_key(key_file_path)

    def _get_encryption_key(self, receiver: str) -> _RSAobj:
        """
        Gets the receiver's encryption key.

        Args:
        receiver: The message recipient's user name.
        """
        key_file_path = self.keys_path / 'public_{}.pem'.format(receiver)
        return self._get_key(key_file_path)

    def _get_key(self, path: Path) -> _RSAobj:
        """
        Return:
        The key, or None if failed.
        """
        if not path.is_file():
            self._logger.error('Key "%s" is missing.', path.name)
            return None
        try:
            key_text = path.read_text()
            key = importKey(key_text)
        except PermissionError as e:
            self._logger.error(e)
            return None
        except (IndexError, TypeError, ValueError) as e:
            self._logger.error('Failed to read key. Reason: %s', e)
            return None
        return key

    def get_message(self, sender: str) -> bytes:
        """
        Gets a message from the server.

        Args:
        sender: The sender's user name.

        Return:
        The message, or ``None`` if no message could be retrieved.
        """
        headers = {}

        try:
            response = requests.get(self.server_url, headers=headers)
        except ConnectionError as e:
            self._logger.error('Connection error: %s', e)
            return

        if response.status_code == requests.codes.ok:
            self._logger.debug('Message received')
        else:
            self._logger.error('Error receiving message. Status code %d',
                               response.status_code)
            return

        return response.content

    def send_message(self, message: bytes, receiver: str) -> bool:
        """
        Encrypts and sends a message to the server.

        Args:
        message: The message.
        receiver: The receiver's user name.

        Return:
        Success status.
        """
        headers = {'sender': self.user_name,
                   'receiver': receiver,
                   'password': self.password}

        msg_encrypted = self._encrypt(message, receiver)

        try:
            response = requests.put(self.server_url, data=msg_encrypted,
                                    headers=headers)
        except ConnectionError as e:
            self._logger.error('Connection error: %s', e)
            return False

        if response.status_code == requests.codes.ok:
            self._logger.debug('Message sent. Response: %s', response.text)
        else:
            self._logger.error('Error sending message. Status code %d',
                               response.status_code)
            return False

        return True


def main():
    logger_name = 'client'
    log_level = logging.DEBUG
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)
    logging.basicConfig()

    user = 'llee'
    pwd = 'eell'
    friend = 'llee'
    message = '<message>'
    client = Client('http://localhost:5001', user, pwd, logger_name)
    client.send_message(message.encode(), friend)
    incoming_msg = client.get_message(friend)
    print('Received message: "{}"'.format(incoming_msg.decode()))


if __name__ == '__main__':
    main()
