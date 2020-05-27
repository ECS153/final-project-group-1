import argparse
from getpass import getpass
import logging

import tkinter as tk

from client import AsyncClient, Message


class FrameScrollableV(tk.Frame):
    """
    A tk frame which can be scrolled vertically. The interior canvas,
    scrollbar, and interior frame can be accessed through the object's
    properties.
    """
    def __init__(self, master=None, cnf={}, **kwargs):
        super().__init__(master=master, cnf=cnf, **kwargs)

        self._scrollbar = tk.Scrollbar(self)
        self._canvas = tk.Canvas(self, height=0, width=0,
                                 yscrollcommand=self._scrollbar.set)
        self._frame = tk.Frame(self._canvas)
        frame_id = self._canvas.create_window((0, 0), window=self._frame,
                                              anchor='nw')
        self._canvas.bind('<Configure>', lambda event:
                          self._canvas.itemconfigure(
                                 frame_id, width=self._canvas.winfo_width()))
        self._frame.bind('<Configure>', lambda event:
                         self._canvas.configure(
                                 scrollregion=self._canvas.bbox('all')))
        self._scrollbar.config(command=self._canvas.yview)
        self._canvas.pack(expand=1, fill='both', side='left')
        self._scrollbar.pack(fill='y', side='right')

    @property
    def canvas(self):
        """
        The area in which the frame contents are displayed in.
        """
        return self._canvas

    @property
    def frame(self):
        """
        The interior frame which contains all the contents.
        """
        return self._frame

    @property
    def scrollbar(self):
        """
        The vertical scrollbar which controls which part of the interior frame
        is shown.
        """
        return self._scrollbar


class GUI(tk.Frame):
    """
    A simple client GUI.
    """
    def __init__(self, client: AsyncClient, master=None):
        super().__init__()
        self.master = master
        self.pack(expand=1, fill='both')
        self._client = client
        self._client.on_new_message = self._on_new_message
        self._to = 'bigboi'
        self._friends = {'bigboi': 'Darian', 'hepl': 'Heping',
                         'llee': 'Lawrence', 'zman': 'Zach'}
        self._init_layout()

    def _init_layout(self):
        self.friends_frame = self._init_friends_frame()
        self.messages_frame = self._init_messages_frame()
        self.input_frame = self._init_input_frame()
        self.friends_frame.pack(fill='x', side='top')
        self.messages_frame.pack(expand=1, fill='both', side='top')
        self.input_frame.pack(fill='x', side='bottom')

    def _init_friends_frame(self) -> tk.Frame:
        frame = tk.Frame(self, bd=1, relief='solid')
        self.friends_buttons = {}
        for user_name, name in self._friends.items():
            button = tk.Radiobutton(
                    frame, text=name, value=user_name,
                    command=self._get_on_friend_click(user_name))
            self.friends_buttons[user_name] = button
            button.pack(side='left')
            button.deselect()
        first_friend = list(self._friends.keys())[0]
        self.friends_buttons[first_friend].select()
        self._to = first_friend
        self._client.receive_from = first_friend
        return frame

    def _init_input_frame(self) -> tk.Frame:
        frame = tk.Frame(self, bd=4, relief='sunken')
        self.input = tk.Entry(frame, width=0)
        self.send_button = tk.Button(frame)
        self.send_button['text'] = 'Send'
        self.send_button['command'] = self._on_send
        self.input.pack(side='left', expand=1, fill='x')
        self.send_button.pack(side='right')
        return frame

    def _init_messages(self, user_name: str, frame: tk.Frame):
        msgs = self._client.get_messages(user_name, unread='false')
        for msg in msgs:
            message = msg.message
            if msg.user_from == self._client.user_name:
                label = tk.Label(frame, anchor='e')
            else:
                label = tk.Label(frame, anchor='w')
            label['text'] = message.decode()
            label.pack(expand=0, fill='x', side='bottom')

    def _init_messages_frame(self) -> tk.Frame:
        frame = tk.Frame(self)
        self.messages_sub_frames = {}
        for user_name in self._friends:
            sub_frame = FrameScrollableV(frame)
            self.messages_sub_frames[user_name] = sub_frame
            self._init_messages(user_name, sub_frame.frame)
            sub_frame.pack_forget()
        self.messages_sub_frames[self._to].pack(expand=1, fill='both')
        return frame

    def _get_on_friend_click(self, user_name):
        def on_friend_click():
            self.messages_sub_frames[self._to].pack_forget()
            self._to = user_name
            self.messages_sub_frames[self._to].pack(expand=1, fill='both')
            self._client.receive_from = user_name
        return on_friend_click

    def _on_new_message(self):
        buffer = self._client.incoming_messages
        while buffer.qsize() > 0:
            msg: Message = buffer.get()
            message = msg.message
            if msg.user_from == self._client.user_name:
                label = tk.Label(self.messages_sub_frames[self._to].frame,
                                 anchor='e')
            else:
                label = tk.Label(self.messages_sub_frames[self._to].frame,
                                 anchor='w')
            label['text'] = message.decode()
            label.pack(expand=0, fill='x', side='bottom')

    def _on_send(self):
        msg = self.input.get().encode()
        if len(msg) == 0:
            return
        message = Message(self._client.user_name, self._to, msg)
        self._client.enqueue_message(message)
        self.input.delete(0, 'end')


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('username', choices=['bigboi', 'hepl', 'llee', 'zman'],
                        help='username')
    parser.add_argument('-u', '--url', default='http://localhost:5001',
                        help='server url')
    parser.add_argument('-p', '--poll_period', default=2, type=int,
                        help='time, in seconds, between each check for new '
                        'messages')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show logging')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='show logging at the debug level')
    return parser.parse_args()


def main():
    args = parse_args()
    password = getpass()

    logger_name = 'client'
    if args.debug:
        logging.getLogger(logger_name).setLevel(logging.DEBUG)
    elif args.verbose:
        logging.getLogger(logger_name).setLevel(logging.WARNING)
    else:
        logging.getLogger(logger_name).setLevel(logging.CRITICAL)
    logging.basicConfig()
    client = AsyncClient(args.url, args.username, password,
                         poll_period=args.poll_period, logger_name=logger_name)

    root = tk.Tk()
    root.minsize(406, 300)
    app = GUI(client, master=root)

    client.start()
    app.mainloop()
    client.quit()


if __name__ == '__main__':
    main()
