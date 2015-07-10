# -*- coding: utf-8 -*-
"""
    pyzco.protocol
    ~~~~~~~~~~~~~~

    Implements the protocol to communicate between agents.

    :copyright: 2013 by Hernan E. Grecco, see AUTHORS for more details.
    :license: BSD, see LICENSE for more details.
"""


import sys
import uuid
import hmac
import json
import hashlib
import time

if sys.version_info < (3, 0):
    import cPickle as pickle
else:
    import pickle

if sys.version_info < (3, 3):
    def compare_digest(a, b):
        return a == b
else:
    compare_digest = hmac.compare_digest


class Protocol(object):
    """Communication protocol

    :param hmac_key: signing key. If not given, messages will not be signed.
    :type hmac_key: str
    :param serializer: the name of serialization protocol. Valid names are::

        - 'pickle': use the highest version available of the pickle format (default).
        - 'pickleN': use the N version of the pickle format.
        - 'json': use json format.

    REP/REQ and PUB/SUB Messages have the following format:

    FRAME 0: HEADER+sender identification+topic (str)
    FRAME 1: serialization protocol (str)
    FRAME 2: content (binary)
    FRAME 3: Message ID (str)
    FRAME 4: HMAC sha1 signature of FRAME 0:4 concatenated with Agent.hmac_key
    """

    HEADER = 'PZC00'
    HEADER_TS = 'PZCT0'
    NEWID = lambda _: uuid.uuid4().urn

    def __init__(self, hmac_key='', serializer=None):
        self.hmac_key = hmac_key.encode('utf-8')
        self.serializer = serializer or 'pickle'

    def parse(self, message, check_sender=None, check_msgid=None, check_timestamp=None):
        """Return a parsed message.

        :param message: the message as obtained by socket.recv_multipart.
        :param check_sender: verify that the sender of the message is the one provided.
        :param check_msgid: verify that the identification of the message is equal to the on provided.
        :return: sender, topic, content, msgid
        :raise: ValueError if messages is malformed or verification fails.
        """

        return self._parse(self.hmac_key, message, check_sender, check_msgid, check_timestamp)

    def _parse(self, key, message, check_sender=None, check_msgid=None, check_timestamp=None):

        try:
            signed, signature = message[:4], message[4]
        except:
            raise ValueError('The message has the wrong number of parts. '
                             'Expected 5, received: {0}'.format(len(message)))

        if key and not compare_digest(self._signature(key, signed), signature):
            raise ValueError('The signature does not match.')

        full_header, serializer, content, msgid = signed
        try:
            header, sender, topic = full_header.decode('utf-8').split('+')
            msgid = msgid.decode('utf-8')
            serializer = serializer.decode('utf-8')
        except:
            raise ValueError('Could not decode or split message parts from UTF-8 bytes.')

        if header != Protocol.HEADER and header != Protocol.HEADER_TS:
            raise ValueError('Wrong header. In server: {0}/{1}, received: {2}'.format(self.HEADER, self.HEADER_TS, header))

        if check_sender and check_sender != sender and sender.find("tcp://*") == -1:
            #todo verify port also
            raise ValueError('Wrong Sender Sender. Sent: {0}, received: {1}'.format(check_sender, sender))

        if check_msgid and check_msgid != msgid:
            raise ValueError('Wrong Message ID. Sent: {0}, received: {1}'.format(check_msgid, msgid))

        try:
            if serializer.startswith('pickle'):
                content = pickle.loads(content)
            elif serializer == 'json':
                content = json.loads(content)
            else:
                raise ValueError('Invalid serializer: {0}'.format(serializer))
        except Exception as ex:
            import traceback
            raise ValueError('Could not deserialize content: {0}'.format(traceback.format_exc()))

        if header == Protocol.HEADER_TS:
            if not check_timestamp:
                content = content[-1] #keep only last message part drops the timestam
            if check_timestamp:
                current_ts = time.time()
                if (current_ts - content[0]) > check_timestamp/1000.:
                    raise TimeoutError("Timestamp")
                content = content[-1]

        return sender, topic, content, msgid

    def format(self, sender, topic='', content='', msgid=None, just_header=False, timestamping=False):
        """Return a formatted message.

        :param sender: unique identifier of the sender as string.
        :param topic: topic of the message as string.
        :param content: content of the message as str.
        :param msgid: message identifier as str. If None, a unique number will be generated
        :param just_header: Return only the header
        :return: formatted message
        :rtype: list of bytes
        """
        return self._format(self.hmac_key, self.serializer, sender, topic, content, msgid, just_header, timestamping)

    def _format(self, key, serializer, sender, topic='', content='', msgid=None, just_header=False, timestamping=False):

        content = content if not timestamping else (self._timestamp(), content)

        try:
            if serializer.startswith('pickle'):
                version = int(serializer[6:] or -1)
                content = pickle.dumps(content, version)
            elif serializer == 'json':
                content = json.dumps(content).encode('utf-8')
            else:
                raise ValueError('Unknown serializer {0}'.format(serializer))
        except Exception as ex:
            import traceback
            raise ValueError('Could not serialize content with tb:{0} topic:{1} sender:{2}'.format(content, topic, sender))

        hdr = self.HEADER if not timestamping else self.HEADER_TS

        if just_header:
            return (hdr + '+' + sender + '+' + topic).encode('utf-8')

        parts = [(hdr + '+' + sender + '+' + topic).encode('utf-8'),
                 serializer.encode('utf-8'),
                 content,
                 (msgid or self.NEWID()).encode('utf-8')]

        return parts + [self._signature(key, parts), ]

    def _signature(self, key, parts):
        if not key:
            return b''
        msg = b''.join(parts)
        return hmac.new(key, msg, digestmod=hashlib.sha1).digest()

    def _timestamp(self):
        return time.time()
