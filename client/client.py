import logging
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
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
    def _padding(self) -> padding.AsymmetricPadding:
        return padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(),
                            None)

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
        decrypted = key.decrypt(message, self._padding)
        return decrypted

    def _encrypt(self, message: bytes, receiver: str) -> bytes:
        """
        Encrypts a message with the receiver's encryption key.

        Args:
        message: The message to encrypt.
        receiver: The message recipient's user name.
        """
        key = self._get_encryption_key(receiver)
        encrypted = key.encrypt(message, self._padding)
        return encrypted

    def _get_decryption_key(self) -> rsa.RSAPrivateKey:
        """
        Gets the user's decryption key.
        """
        key_file_path = self.keys_path / 'private_{}.pem'.format(
                self.user_name)
        return self._get_key(key_file_path, private=True)

    def _get_encryption_key(self, receiver: str) -> rsa.RSAPublicKey:
        """
        Gets the receiver's encryption key.

        Args:
        receiver: The message recipient's user name.
        """
        key_file_path = self.keys_path / 'public_{}.pem'.format(receiver)
        return self._get_key(key_file_path)

    def _get_key(self, path: Path, private=False):
        """
        Return:
        The key, or None if failed.
        """
        if not path.is_file():
            self._logger.error('Key "%s" is missing.', path.name)
            return None
        try:
            key_bytes = path.read_bytes()
            if private:
                key = serialization.load_pem_private_key(
                        key_bytes, None, default_backend())
            else:
                key = serialization.load_pem_public_key(
                        key_bytes, default_backend())
        except PermissionError as e:
            self._logger.error(e)
            return None
        except (TypeError, UnsupportedAlgorithm, ValueError) as e:
            self._logger.error('Failed to read key. Reason: %s', e)
            return None
        if (private and not isinstance(key, rsa.RSAPrivateKey)
                or not private and not isinstance(key, rsa.RSAPublicKey)):
            self._logger.error('Unsupported key type %s.', type(key))
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
        headers = {'sender': self.user_name,
                   'receiver': sender,
                   'password': self.password}


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

        try:
            decrypted = self._decrypt(response.content)
        except Exception as e:
            self._logger.error('Failed to decrypt message. %s', e)
            return None

        return decrypted

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

        try:
            msg_encrypted = self._encrypt(message, receiver)
        except Exception as e:
            self._logger.error('Failed to encrypt message. %s', e)
            return False

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
