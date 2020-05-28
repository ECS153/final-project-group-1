from base64 import b64decode, b64encode
import logging
from pathlib import Path
from queue import Queue
from threading import Event, Thread
from typing import Callable, List

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import requests
from requests import Response
from requests.exceptions import ConnectionError


class Message:
    """
    A byte message wrapper with some metadata.
    """
    def __init__(self, user_from: str, user_to: str, message: bytes):
        self._from = user_from
        self._to = user_to
        self._messsage = message

    @property
    def message(self):
        return self._messsage

    @property
    def user_from(self):
        """
        The username of the person sending the message.
        """
        return self._from

    @property
    def user_to(self):
        """
        The username of the person receiving the message.
        """
        return self._to


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
        self.password = password
        self.server_url = server_url
        self.user_name = user_name

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

    def get_messages(self, sender: str, unread: str = 'true') -> List[Message]:
        """
        Gets a message from the server.

        Args:
        sender: The sender's user name.

        Return:
        The message, or ``None`` if no message could be retrieved.
        """
        headers = {'username': self.user_name,
                   'contact': sender,
                   'password': self.password,
                   'unread': unread}

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

        messages = self._response_to_messages(response)

        return messages

    def _message_to_request_body(self, message: bytes, receiver: str) -> dict:
        """
        Creates a HTTP put request body for sending a message.

        Return:
        The body, or None upon failure.
        """
        msg_encrypted = {}
        try:
            msg_encrypted[receiver] = self._encrypt(message, receiver)
            msg_encrypted[self.user_name] = self._encrypt(message,
                                                          self.user_name)
        except Exception as e:
            self._logger.error('Failed to encrypt message. %s', e)
            return None

        body = {}
        for username, msg in msg_encrypted.items():
            body[username] = b64encode(msg).decode()

        return body

    def _response_to_messages(self, response: Response) -> List[Message]:
        """
        Parses the messages from an HTTP get response. Messages are ordered
        from oldest to newest. The receiver is assumed to be the value of
        ``self.user_name``.

        Return:
        A list of messages, or None upon failure.
        """
        try:
            body = response.json()
        except ValueError as e:
            self._logger.error('Failed to parse JSON from response: %s', e)
            return None

        messages = []
        for msg in body:
            encrypted = b64decode(msg['message'].encode())
            try:
                decrypted = self._decrypt(encrypted)
            except Exception as e:
                self._logger.error('Failed to decrypt message. %s', e)
                return None
            messages.append(Message(msg['sender'], self.user_name, decrypted))

        return messages

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

        request_body = self._message_to_request_body(message, receiver)
        if request_body is None:
            self._logger.error('Failed to generate request body.')
            return False

        try:
            response = requests.put(self.server_url, data=request_body,
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


class AsyncClient(Client):
    def __init__(self, server_url: str, user_name: str, password: str,
                 poll_period: float = 1.0, logger_name=None):
        """
        Creates a new asynchronous client which can communicate with a server.
        This client has two threads dedicated for sending and receiving
        messages. The client must be started before any messages are sent or
        received.

        Args:
        server_url: The server's url. Example: 'https://server.com'
        user_name: The user's user name.
        password: The user's password.
        poll_period: Time in seconds to wait before polling the server for new
        incoming messages.
        logger_name: The name of the logger to use.
        """
        self._receiver = ReceiverThread(self)
        self._sender = SenderThread(self)
        self.poll_period = poll_period
        super().__init__(server_url, user_name, password,
                         logger_name=logger_name)

    @property
    def incoming_messages(self) -> Queue:
        """
        A buffer containing received messages in the form of ``Message``s.
        """
        return self._receiver.buffer

    @property
    def poll_period(self) -> float:
        return self._receiver.poll_period

    @poll_period.setter
    def poll_period(self, period: float):
        """
        Time in seconds to wait before polling the server for new incoming
        messages. Setting the period resets the time.
        """
        if period < 0:
            raise ValueError('Polling period must be non-negative.')
        self._receiver.poll_period = period

    def enqueue_message(self, message: Message):
        """
        Queue a message to be sent.
        """
        self._sender.enqueue(message)

    @property
    def on_new_message(self) -> Callable[[], None]:
        return self._receiver.callback

    @on_new_message.setter
    def on_new_message(self, function: Callable[[], None]):
        """
        Called whenever a new message has been received.
        """
        self._receiver.callback = function

    @property
    def receive_from(self) -> str:
        return self._receiver.user_from

    @receive_from.setter
    def receive_from(self, user_from: str):
        self._receiver.user_from = user_from

    def quit(self):
        """
        Stops the client's sending and receiving threads. They cannot be
        restarted.
        """
        self._receiver.request_quit()
        self._sender.request_quit()
        self._receiver.join()
        self._sender.join()

    def start(self):
        """
        Starts the client's sending and receiving threads.
        """
        self._receiver.start()
        self._sender.start()


class QuittableThread(Thread):
    def __init__(self, client: Client):
        """
        Constructs a thread which you can request to quit. Child classes can
        wait on this class's event property to facilitate fast quitting in the
        case when the thread needs to sleep. This is because the event is
        triggered immediately after a request to quit.
        """
        super().__init__()
        self._client = client
        self._event = Event()
        self._quit_requested = False

    @property
    def event(self):
        return self._event

    @property
    def quit_requested(self):
        return self._quit_requested

    def start(self):
        self.event.clear()
        super().start()

    def request_quit(self):
        self._quit_requested = True
        self._event.set()


class ReceiverThread(QuittableThread):
    def __init__(self, client: Client, poll_period: float = 1.0):
        """
        Construct a thread which periodically receives messages through a
        client.

        Args:
        client: The client used for receiving messages.
        poll_period: Time in seconds to wait before polling the server for new
        incoming messages.
        """
        super().__init__(client)
        self._callback = None
        self._queue = Queue()
        self._from = None
        self.poll_period = poll_period

    @property
    def buffer(self) -> Queue:
        """
        A queue containing received messages.
        """
        return self._queue

    @property
    def callback(self) -> Callable[[], None]:
        return self._callback

    @callback.setter
    def callback(self, func: Callable[[], None]):
        """
        A function which is called when a new message is received.
        """
        self._callback = func

    @property
    def poll_period(self) -> float:
        return self._poll_period

    @poll_period.setter
    def poll_period(self, period: float):
        """
        Time in seconds to wait before polling the server for new incoming
        messages. Setting the period resets the timer.
        """
        if period < 0:
            raise ValueError('Polling period must be non-negative.')
        self._poll_period = period
        self.event.set()

    @property
    def user_from(self) -> str:
        return self._from

    @user_from.setter
    def user_from(self, user_from: str):
        self._from = user_from

    def run(self):
        while not self.quit_requested:
            user_from = self.user_from  # Take snapshot for thread safety.

            # Try to get a message.
            if user_from is None:
                msgs = []
            else:
                msgs = self._client.get_messages(user_from)
            if msgs is None:
                msgs = []

            # Process the messages if there are any.
            for message in msgs:
                self._queue.put(message)
                if self.callback is not None:
                    self.callback()

            # Interruptible sleep.
            event_set = True
            while event_set and not self.quit_requested:
                event_set = self.event.wait(self.poll_period)
            self.event.clear()


class SenderThread(QuittableThread):
    def __init__(self, client: Client):
        """
        Construct a thread which sends messages through a client. Quits only
        when quit has been requested and all queued messages have been sent.

        Args:
        client: The client used for sending messages.
        """
        super().__init__(client)
        self._queue = Queue()

    def run(self):
        while not self._queue.empty() or not self.quit_requested:
            while self._queue.empty() and not self.quit_requested:
                self._event.wait()
            self._event.clear()
            if not self._queue.empty():
                msg = self._queue.get()
                success = self._client.send_message(msg.message, msg.user_to)
                if not success:
                    self._queue.put(msg)

    def enqueue(self, message: Message):
        """
        Queue a message to be sent.
        """
        self._queue.put(message)
        self._event.set()
