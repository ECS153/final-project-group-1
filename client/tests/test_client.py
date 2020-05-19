from datetime import datetime
from pathlib import Path
from time import sleep
from typing import List

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import pytest
from requests import PreparedRequest
from requests_mock import CookieJar, Mocker

from ..client import AsyncClient, Client, Message


friend_name = ''
message = ''
messages_in = []
messages_out = []
messages_received = []
messages_sent = []
password = ''
test_async = False
url = 'http://server.com'
user_name = ''
users = ['bigboi', 'hepl', 'llee', 'zman']


class Context:
    headers: dict
    status_code: int
    reason: str
    cookies: CookieJar


def check_headers(headers: dict):
    check_headers_simple(headers)
    assert headers['password'] == password
    assert headers['receiver'] == friend_name
    assert headers['sender'] == user_name


def check_headers_simple(headers: dict):
    assert 'password' in headers
    assert 'receiver' in headers
    assert 'sender' in headers


def check_messages_in(expected_messages: List[Message]):
    assert len(expected_messages) == len(messages_received)
    for expected in expected_messages:
        assert message_in_list(expected, messages_received)


def check_messages_out(expected_messages: List[Message]):
    assert len(expected_messages) == len(messages_sent)
    for expected in expected_messages:
        assert message_in_list(expected, messages_sent)


def create_messages(user_from: str, user_to: str, messages: List[str]) -> \
        List[Message]:
    return [Message(user_from, user_to, msg.encode()) for msg in messages]


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
    headers = request.headers
    if test_async:
        check_headers_simple(headers)
    else:
        check_headers(headers)
    if headers['receiver'] not in users or headers['sender'] not in users:
        context.status_code = 404
        context.reason = 'User not found.'
        return b''

    if test_async:
        if len(messages_in) == 0:
            return b''
        msg = messages_in.pop(0)
        encrypted = encrypt(msg.message, msg.user_to)
    else:
        encrypted = encrypt(message.encode(), user_name)
    return encrypted


def receive_message(client: Client):
    return client.get_message(friend_name)


def receive_messages_async(client: AsyncClient, message_count: int,
                           timeout: float = 1):
    start = datetime.now()
    while (client.incoming_messages.qsize() < message_count
           and (datetime.now() - start).total_seconds() < timeout):
        sleep(0.01)
    while client.incoming_messages.qsize() != 0:
        messages_received.append(client.incoming_messages.get())


def get_padding() -> padding.AsymmetricPadding:
    return padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)


def keys_dir():
    return Path(__file__).parent.parent / 'keys'


def message_in_list(message: Message, message_list: List[Message]) -> bool:
    message_text = message.message.decode()
    message_from = message.user_from
    message_to = message.user_to
    for msg in message_list:
        if (message_text == msg.message.decode()
                and message_from == msg.user_from
                and message_to == msg.user_to):
            return True
    return False


def new_async_client() -> AsyncClient:
    return AsyncClient(url, user_name, password, poll_period=0.01)


def new_client() -> Client:
    return Client(url, user_name, password)


def put_content(request: PreparedRequest, context: Context):
    headers = request.headers
    if test_async:
        check_headers_simple(headers)
    else:
        check_headers(headers)
    if headers['receiver'] not in users or headers['sender'] not in users:
        context.status_code = 404
        context.reason = 'User not found.'
        return b''

    content = request.body
    decrypted = decrypt(content, friend_name)

    if test_async:
        msg = Message(headers['sender'], headers['receiver'], decrypted)
        messages_sent.append(msg)
    else:
        assert decrypted.decode() == message


def send_message(client: Client):
    return client.send_message(message.encode(), friend_name)


def send_messages_async(client: AsyncClient):
    for msg in messages_out:
        client.enqueue_message(msg)


def set_globals(l_user_name=user_name, l_friend_name=friend_name,
                l_password=password, l_message=message,
                l_test_async=test_async, l_messages_in=messages_in,
                l_messages_out=messages_out):
    global user_name
    global friend_name
    global password
    global message
    global messages_in
    global messages_out
    global test_async
    user_name = l_user_name
    friend_name = l_friend_name
    password = l_password
    message = l_message
    messages_in = l_messages_in[:]
    messages_out = l_messages_out[:]
    test_async = l_test_async


@pytest.fixture(autouse=True)
def mock_server(requests_mock: Mocker):
    global messages_received
    global messages_sent
    messages_received = []
    messages_sent = []
    requests_mock.get(url, content=get_content)
    requests_mock.put(url, content=put_content)


def test_put_server_error(requests_mock: Mocker):
    requests_mock.put(url, status_code=404)
    set_globals('llee', 'zman', 'pwd1', 'Hello world!')
    client = new_client()
    assert False == send_message(client)


def test_put_1():
    set_globals('llee', 'zman', 'pwd1', 'Hello world!')
    client = new_client()
    assert True == send_message(client)


def test_put_2():
    set_globals('hepl', 'hepl', 'pwd2', 'test_put_2')
    client = new_client()
    assert True == send_message(client)


def test_put_3():
    set_globals('zman', 'bigboi', 'pwd3', 'qwerty')
    client = new_client()
    assert True == send_message(client)


def test_put_fail_unknown_friend():
    set_globals('llee', 'foo', 'pwd', 'asdf')
    client = new_client()
    assert False == send_message(client)


def test_put_fail_unknown_user():
    set_globals('foo', 'llee', 'pwd', 'asdf')
    client = new_client()
    assert False == send_message(client)


def test_get_server_error(requests_mock: Mocker):
    requests_mock.get(url, status_code=404)
    set_globals('llee', 'zman', 'pwd1', 'Hello world!')
    client = new_client()
    received = receive_message(client)
    assert received == None


def test_get_1():
    set_globals('llee', 'zman', 'pwd1', 'Hello world!')
    client = new_client()
    received = receive_message(client)
    assert received.decode() == message


def test_get_2():
    set_globals('hepl', 'hepl', 'pwd2', 'test_put_2')
    client = new_client()
    received = receive_message(client)
    assert received.decode() == message


def test_get_3():
    set_globals('zman', 'bigboi', 'pwd3', 'qwerty')
    client = new_client()
    received = receive_message(client)
    assert received.decode() == message


def test_get_fail_unknown_friend():
    set_globals('llee', 'foo', 'pwd', 'asdf')
    client = new_client()
    received = receive_message(client)
    assert received == None


def test_get_fail_unknown_user():
    set_globals('foo', 'llee', 'pwd', 'asdf')
    client = new_client()
    received = receive_message(client)
    assert received == None


def test_async_put_1():
    user_name = 'llee'
    friend_name = 'zman'
    messages_out = create_messages(user_name, friend_name, ['msg1', 'msg2'])
    set_globals(user_name, friend_name, 'pwd1', '', True, [], messages_out)
    client = new_async_client()
    client.start()
    send_messages_async(client)
    client.quit()
    check_messages_out(messages_out)


def test_async_get_1():
    user_name = 'llee'
    friend_name = 'zman'
    messages_in = create_messages(friend_name, user_name, ['msg1', 'msg2'])
    set_globals(user_name, friend_name, 'pwd1', '', True, messages_in, [])
    client = new_async_client()
    client.receive_from = friend_name
    client.start()
    receive_messages_async(client, len(messages_in))
    client.quit()
    check_messages_in(messages_in)


def test_async_get_put_1():
    user_name = 'bigboi'
    friend_name = 'hepl'
    messages_in = create_messages(friend_name, user_name, ['msg1', 'msg2'])
    messages_out = create_messages(user_name, friend_name, ['msg3', 'msg4'])
    set_globals(user_name, friend_name, 'pwd1', '', True, messages_in,
                messages_out)
    client = new_async_client()
    client.receive_from = friend_name
    client.start()
    send_messages_async(client)
    receive_messages_async(client, len(messages_in))
    client.quit()
    check_messages_in(messages_in)
    check_messages_out(messages_out)
