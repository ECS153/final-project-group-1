from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import pytest
from requests import PreparedRequest
from requests_mock import CookieJar, Mocker

from ..client import Client


friend_name = ''
message = ''
password = ''
url = 'http://server.com'
user_name = ''


class Context:
    headers: dict
    status_code: int
    reason: str
    cookies: CookieJar


def check_headers(headers: dict):
    assert 'password' in headers
    assert 'receiver' in headers
    assert 'sender' in headers
    assert headers['password'] == password
    assert headers['receiver'] == friend_name
    assert headers['sender'] == user_name


def decrypt(msg: bytes, user: str):
    key_path = keys_dir() / f'private_{user}.pem'
    key_content = key_path.read_bytes()
    key = serialization.load_pem_private_key(key_content, None,
                                             default_backend())
    return key.decrypt(msg, get_padding())


def encrypt(msg: bytes, user: str):
    key_path = keys_dir() / f'public_{user}.pem'
    key_content = key_path.read_bytes()
    key = serialization.load_pem_public_key(key_content, default_backend())
    return key.encrypt(msg, get_padding())


def get_content(request: PreparedRequest, context: Context):
    encrypted = encrypt(message.encode(), user_name)
    return encrypted


def receive_message(client: Client):
    received_message = client.get_message(friend_name)
    assert received_message.decode() == message


def get_padding() -> padding.AsymmetricPadding:
    return padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)


def keys_dir():
    return Path(__file__).parent.parent / 'keys'


def new_client() -> Client:
    return Client(url, user_name, password)


def put_content(request: PreparedRequest, context: Context):
    check_headers(request.headers)
    content = request.body
    decrypted = decrypt(content, friend_name)
    assert decrypted.decode() == message


def send_message(client: Client):
    client.send_message(message.encode(), friend_name)


def set_globals(l_user_name=user_name, l_friend_name=friend_name,
                l_password=password, l_message=message):
    global user_name
    global friend_name
    global password
    global message
    user_name = l_user_name
    friend_name = l_friend_name
    password = l_password
    message = l_message


@pytest.fixture(autouse=True)
def mock_server(requests_mock: Mocker):
    requests_mock.get(url, content=get_content)
    requests_mock.put(url, content=put_content)


def test_put_1():
    set_globals('llee', 'zman', 'pwd1', 'Hello world!')
    client = new_client()
    send_message(client)


def test_put_2():
    set_globals('hepl', 'hepl', 'pwd2', 'test_put_2')
    client = new_client()
    send_message(client)


def test_put_3():
    set_globals('zman', 'bigboi', 'pwd3', 'qwerty')
    client = new_client()
    send_message(client)


def test_get_1():
    set_globals('llee', 'zman', 'pwd1', 'Hello world!')
    client = new_client()
    receive_message(client)


def test_get_2():
    set_globals('hepl', 'hepl', 'pwd2', 'test_put_2')
    client = new_client()
    receive_message(client)


def test_get_3():
    set_globals('zman', 'bigboi', 'pwd3', 'qwerty')
    client = new_client()
    receive_message(client)
