# Copyright IBM Corp. 2017 All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import re
import sys
import uuid
import logging
from copy import copy
from hashlib import sha256

from hfc.protos.common import common_pb2
from hfc.protos.common.common_pb2 import BlockMetadataIndex, Status
from hfc.protos.orderer import ab_pb2
from hfc.protos.peer.transaction_pb2 import TxValidationCode
from hfc.protos.utils import create_seek_payload, \
    create_envelope
from hfc.util.utils import current_timestamp, \
    build_header, build_channel_header, pem_to_der
from hfc.fabric.transaction.tx_context import TXContext
from hfc.fabric.transaction.tx_proposal_request import TXProposalRequest
from hfc.fabric.block_decoder import BlockDecoder, FilteredBlockDecoder

_logger = logging.getLogger(__name__ + ".channel_eventhub")
_logger.setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

NO_START_STOP = 0
START_ONLY = 1
END_ONLY = 2
START_AND_END = 3


def mylog(message):
    logger.error(f'event hub: {message}')

class EventRegistration(object):
    """A class represents event registration."""

    def __init__(self, onEvent=None, unregister=True, disconnect=False):
        self.onEvent = onEvent
        self.unregister = unregister
        self.disconnect = disconnect


class ChaincodeRegistration(object):
    """A class represents chaincode registration."""

    def __init__(self, ccid, pattern, er, as_array):
        self.uuid = uuid.uuid4().hex
        self.ccid = ccid
        self.pattern = pattern
        self.er = er
        self.as_array = as_array


class ChannelEventHub(object):
    """A class represents channel event hub."""

    def __init__(self, peer, channel_name, requestor):
        self._peer = peer
        self._requestor = requestor
        self._channel_name = channel_name

        self.stream = None
        self._start = None
        self._stop = None
        self._filtered = True
        self._as_array = False
        self._reg_nums = []
        self._tx_ids = {}
        self._reg_ids = {}
        self._connected = False
        self._start_stop_action = {}
        self._start_stop_connect = False
        self._last_seen = None
        self._signed_event = None

        self._ending_block_seen = False
        self._ending_block_newest = False

        self._ending_block_newest = False

    @property
    def connected(self):
        """Get the connected
        :return: The connected
        """
        return self._connected

    @connected.setter
    def connected(self, connected):
        """Set the connected

        :param connected: the connected
        :return:
        """
        self._connected = connected

    def _create_seek_info(self, start=None, stop=None):
        behavior = 'BLOCK_UNTIL_READY'

        # build start
        seek_start = ab_pb2.SeekPosition()
        if start is None or start == 'newest':
            seek_start.newest.CopyFrom(ab_pb2.SeekNewest())
        elif start == 'oldest':
            seek_start.oldest.CopyFrom(ab_pb2.SeekOldest())
        else:
            seek_specified_start = ab_pb2.SeekSpecified()
            seek_specified_start.number = start
            seek_start.specified.CopyFrom(seek_specified_start)

        # build stop
        seek_stop = ab_pb2.SeekPosition()
        if stop == 'newest':
            self._ending_block_newest = True
            seek_stop.newest.CopyFrom(ab_pb2.SeekNewest())
            behavior = 'FAIL_IF_NOT_READY'
        elif start == 'oldest':
            seek_stop.oldest.CopyFrom(ab_pb2.SeekOldest())
            behavior = 'FAIL_IF_NOT_READY'
        else:
            seek_specified_stop = ab_pb2.SeekSpecified()
            if stop is not None:
                seek_specified_stop.number = stop
                behavior = 'FAIL_IF_NOT_READY'
            else:
                seek_specified_stop.number = sys.maxsize
            seek_stop.specified.CopyFrom(seek_specified_stop)

        # seek info with all parts
        seek_info = ab_pb2.SeekInfo()
        seek_info.start.CopyFrom(seek_start)
        seek_info.stop.CopyFrom(seek_stop)

        # BLOCK_UNTIL_READY will mean hold the stream open and keep sending
        # as the blocks come in
        # FAIL_IF_NOT_READY will mean if the block is not there throw an error
        seek_info.behavior = ab_pb2.SeekInfo.SeekBehavior.Value(behavior)

        return seek_info

    def _get_stream(self):
        """get the events of the channel.

        :return: the events in success or None in fail.
        """
        mylog('_get_stream')
        _logger.info("create peer delivery stream")

        if self._signed_event is not None:
            return self._peer.delivery(self._signed_event,
                                       filtered=self._filtered)

        seek_info = self._create_seek_info(self._start, self._stop)

        kwargs = {}
        if self._peer._client_cert_path:
            with open(self._peer._client_cert_path, 'rb') as f:
                b64der = pem_to_der(f.read())
                kwargs['tls_cert_hash'] = sha256(b64der).digest()

        tx_context = TXContext(self._requestor, self._requestor.cryptoSuite,
                               TXProposalRequest())

        seek_info_header = build_channel_header(
            common_pb2.HeaderType.Value('DELIVER_SEEK_INFO'),
            tx_context.tx_id,
            self._channel_name,
            current_timestamp(),
            tx_context.epoch,
            **kwargs
        )

        seek_header = build_header(
            tx_context.identity,
            seek_info_header,
            tx_context.nonce)

        seek_payload_bytes = create_seek_payload(seek_header, seek_info)
        sig = tx_context.sign(seek_payload_bytes)
        envelope = create_envelope(sig, seek_payload_bytes)

        # this is a stream response
        return self._peer.delivery(envelope, filtered=self._filtered)

    def check_start_stop_connect(self, start=None, stop=None):
        if start is not None or stop is not None:
            if self._start_stop_action:
                raise Exception('Not able to connect with start/stop block'
                                ' when a registered listener has those options.')

            if start == 'last_seen':
                start = self._last_seen

            if not ((isinstance(start, int)
                     or start in ('oldest', 'newest'))
                    or start is None):
                raise Exception('start value must be: last_seen, oldest, newest or an integer')

            if stop == 'last_seen':
                stop = self._last_seen

            if not ((isinstance(stop, int)
                     or stop == 'newest')
                    or stop is None):
                raise Exception('stop value must be: last_seen, newest, sys.maxsize or an integer')

            if isinstance(start, int) \
                    and isinstance(stop, int)\
                    and start > stop:
                raise Exception('start cannot be greater than stop')

            self._start = start
            self._stop = stop

            self._start_stop_connect = True

    def check_start_stop_listener(self, start=None, stop=None):

        result = NO_START_STOP

        if self._start_stop_action:
            raise Exception('This ChannelEventHub is not open to event'
                            ' listener registrations')

        if start is not None or stop is not None:
            if self.have_registrations():
                raise Exception('Only one event registration is allowed when'
                                ' start/stop block are used.')

            if self._start_stop_connect:
                raise Exception('The registration with a start/stop block'
                                ' must be done before calling connect()')

            if stop is not None:
                if not (isinstance(stop, int)
                        or stop == 'newest'):
                    raise Exception('stop must be an integer, newest or'
                                    ' sys.maxsize')
                else:
                    result = END_ONLY

            if start is not None:
                if not isinstance(start, int):
                    raise Exception('start must be an integer')
                else:
                    # will move result to START_ONLY or START_AND_END
                    result += 1

            if isinstance(start, int) \
                    and isinstance(stop, int) \
                    and start > stop:
                raise Exception('start cannot be greater than stop')

            self._start = start
            self._stop = stop

        return result

    def _processBlockEvents(self, block):
        mylog('_processBlockEvents')
        for reg_num in self._reg_nums:

            if reg_num.unregister:
                mylog(f'_processBlockEvents unregisterBlockEvent {reg_num}')
                self.unregisterBlockEvent(reg_num)

            if reg_num.onEvent is not None:
                mylog(f'_processBlockEvents onEvent {reg_num}')
                reg_num.onEvent(block)

            if reg_num.disconnect:
                mylog(f'_processBlockEvents disconnect {reg_num}')
                self.disconnect()

    def registerBlockEvent(self, unregister=True,
                           start=None, stop=None,
                           disconnect=False, onEvent=None):
        mylog('registerBlockEvent')
        startstop_mode = self.check_start_stop_listener(start, stop)

        reg_num = EventRegistration(onEvent,
                                    unregister=unregister,
                                    disconnect=disconnect)

        def unregister_action():
            return self.unregisterBlockEvent(reg_num)

        self._on_end_actions(reg_num, unregister_action, startstop_mode,
                             unregister, disconnect)

        self._reg_nums.append(reg_num)
        return reg_num

    def unregisterBlockEvent(self, reg_num):
        mylog('unregisterBlockEvent')
        self._reg_nums.remove(reg_num)

    def handle_filtered_tx(self, block, tx_id, er):
        mylog('handle_filtered_tx')
        for ft in block['filtered_transactions']:
            if tx_id == ft['txid'] or tx_id == 'all':

                if er.onEvent is not None:
                    mylog(f'handle_filtered_tx onEvent {tx_id}')
                    er.onEvent(tx_id, ft['tx_validation_code'],
                               block['number'])
                if er.unregister:
                    mylog(f'handle_filtered_tx unregister {tx_id}')
                    self.unregisterTxEvent(tx_id)
                if er.disconnect:
                    mylog(f'handle_filtered_tx disconnect {tx_id}')
                    self.disconnect()

    def handle_full_tx(self, block, tx_id, er):
        mylog('handle_full_tx')
        for index, data in enumerate(block['data']['data']):
            channel_header = data['payload']['header']['channel_header']
            if tx_id == channel_header['tx_id'] or tx_id == 'all':

                if er.onEvent is not None:
                    txFilter = BlockMetadataIndex.Value('TRANSACTIONS_FILTER')
                    txStatusCodes = block['metadata']['metadata'][txFilter]
                    status = TxValidationCode.Name(txStatusCodes[index])
                    er.onEvent(tx_id, status, block['header']['number'])
                if er.unregister:
                    mylog('handle_full_tx disconnect unregister')
                    self.unregisterTxEvent(tx_id)
                if er.disconnect:
                    mylog('handle_full_tx disconnect')
                    self.disconnect()

    def _processTxEvents(self, block):
        mylog('_processTxEvents')
        for tx_id, er in copy(self._tx_ids).items():
            # filtered block case
            if self._filtered:
                self.handle_filtered_tx(block, tx_id, er)
            else:
                self.handle_full_tx(block, tx_id, er)

    def registerTxEvent(self, tx_id, unregister=None,
                        start=None, stop=None,
                        disconnect=False, onEvent=None):
        mylog(f'registerTxEvent {tx_id} disconnect={disconnect} unregister={unregister}')
        startstop_mode = self.check_start_stop_listener(start, stop)

        if tx_id == 'all' and unregister is None:
            unregister = False
        else:
            unregister = True

        er = EventRegistration(onEvent,
                               unregister=unregister,
                               disconnect=disconnect)

        def unregister_action():
            mylog(f'unregister_action {tx_id}')
            return self.unregisterTxEvent(tx_id)

        self._on_end_actions(er, unregister_action,
                             startstop_mode, unregister, disconnect)

        self._tx_ids[tx_id] = er
        return tx_id

    def unregisterTxEvent(self, tx_id):
        mylog('unregisterTxEvent')
        if tx_id in self._tx_ids:
            del self._tx_ids[tx_id]

    def _queue_chaincode_event(self, chaincode_event, block_number,
                               tx_id, tx_status, all_events):
        mylog('_queue_chaincode_event')
        for ccid in copy(self._reg_ids).keys():
            mylog(f'_queue_chaincode_event 1 {ccid}')
            for cr in self._reg_ids[ccid]:
                mylog(f'_queue_chaincode_event 1 {ccid} {cr.ccid} {cr.pattern}')
                if chaincode_event['chaincode_id'] == cr.ccid and \
                        re.match(cr.pattern, chaincode_event['event_name']):

                    mylog(f'_queue_chaincode_event 1 {ccid} {cr.ccid} {cr.pattern} match')

                    evt = {
                        'chaincode_event': chaincode_event,
                        'block_num': block_number,
                        'tx_id': tx_id,
                        'tx_status': tx_status
                    }

                    if ccid not in all_events:
                        mylog(f'_queue_chaincode_event 2')
                        all_events[ccid] = [{
                            cr.uuid: {
                                'cr': cr,
                                'evts': [evt]
                            }
                        }]
                    else:
                        mylog(f'_queue_chaincode_event 3')
                        for x in all_events[ccid]:
                            mylog(f'_queue_chaincode_event 4')
                            _uuid = next(iter(x.keys()))
                            if _uuid == cr.uuid:
                                mylog(f'_queue_chaincode_event 5')
                                x[_uuid]['evts'] += [evt]
                                break
                        else:
                            mylog(f'_queue_chaincode_event 6')
                            all_events[ccid].append({
                                cr.uuid: {
                                    'cr': cr,
                                    'evts': [evt]
                                }
                            })

    def handle_filtered_chaincode(self, block, all_events):

        mylog('handle_filtered_chaincode')
        for ft in block['filtered_transactions']:
            mylog(f'handle_filtered_chaincode {ft}')
            if 'transaction_actions' in ft:
                mylog(f'handle_filtered_chaincode 1')
                tx_actions = ft['transaction_actions']
                for chaincode_action in tx_actions['chaincode_actions']:
                    mylog(f'handle_filtered_chaincode 1 {chaincode_action}')
                    chaincode_event = chaincode_action['chaincode_event']
                    # need to remove the payload since with filtered blocks it
                    # has an empty byte array value which is not the real value
                    # we do not want the listener to think that is the value
                    del chaincode_event['payload']
                    self._queue_chaincode_event(chaincode_event,
                                                block['number'],
                                                ft['txid'],
                                                ft['tx_validation_code'],
                                                all_events)

    def _handle_full_chaincode(self, tx, block_number, tx_id,
                               tx_status, all_events):
        mylog('_handle_full_chaincode')
        if 'actions' in tx:
            mylog('_handle_full_chaincode actions')
            for t in tx['actions']:
                mylog('_handle_full_chaincode actions action')
                ppl_r_p = t['payload']['action']['proposal_response_payload']
                chaincode_event = ppl_r_p['extension']['events']
                self._queue_chaincode_event(chaincode_event,
                                            block_number,
                                            tx_id,
                                            tx_status,
                                            all_events)

    def handle_full_chaincode(self, block, all_events):
        mylog('handle_full_chaincode')
        if 'data' in block:
            mylog('handle_full_chaincode block')
            for index, data in enumerate(block['data']['data']):
                mylog(f'handle_full_chaincode block index={index}')
                payload = data['payload']
                channel_header = payload['header']['channel_header']

                # only ENDORSER_TRANSACTION have chaincode events
                if channel_header['type'] == 3:
                    tx = payload['data']
                    txFilter = BlockMetadataIndex.Value('TRANSACTIONS_FILTER')
                    txStatusCodes = block['metadata']['metadata'][txFilter]
                    tx_status = TxValidationCode.Name(txStatusCodes[index])
                    tx_id = channel_header['tx_id']
                    mylog(f'handle_full_chaincode block index={index} type=3 tx_status={tx_status} tx_id={tx_id}')
                    self._handle_full_chaincode(tx,
                                                block['header']['number'],
                                                tx_id,
                                                tx_status,
                                                all_events)

    def _processChaincodeEvents(self, block):

        mylog('_processChaincodeEvents')
        if len(self._reg_ids.keys()):
            mylog('_processChaincodeEvents 1')
            all_events = {}
            if self._filtered:
                self.handle_filtered_chaincode(block, all_events)
            else:
                self.handle_full_chaincode(block, all_events)

            for events in all_events.values():
                mylog('_processChaincodeEvents 2')
                for e in events:
                    mylog('_processChaincodeEvents 3')
                    for x in e.values():
                        mylog('_processChaincodeEvents 4')
                        if x['cr'].er.onEvent is not None:
                            mylog('_processChaincodeEvents 5')
                            if x['cr'].as_array:
                                mylog('_processChaincodeEvents 6')
                                x['cr'].er.onEvent(x['evts'])
                            else:
                                mylog('_processChaincodeEvents 7')
                                for e in x['evts']:
                                    mylog('_processChaincodeEvents 8')
                                    x['cr'].er.onEvent(e['chaincode_event'],
                                                       e['block_num'],
                                                       e['tx_id'],
                                                       e['tx_status'])

                        if x['cr'].er.unregister:
                            mylog('_processChaincodeEvents 9')
                            self.unregisterChaincodeEvent(x['cr'])

                        if x['cr'].er.disconnect:
                            mylog('_processChaincodeEvents disconnect')
                            self.disconnect()

    def registerChaincodeEvent(self, ccid, pattern, unregister=False,
                               start=None, stop=None,
                               as_array=None,
                               disconnect=False, onEvent=None):

        mylog('registerChaincodeEvent')
        startstop_mode = self.check_start_stop_listener(start, stop)

        if as_array is None:
            as_array = self._as_array

        er = EventRegistration(onEvent, unregister=unregister,
                               disconnect=disconnect)
        cr = ChaincodeRegistration(ccid, pattern, er, as_array)

        def unregister_action():
            return self.unregisterChaincodeEvent(cr)

        self._on_end_actions(cr, unregister_action, startstop_mode,
                             unregister, disconnect)

        if ccid in self._reg_ids:
            self._reg_ids[ccid].append(cr)
        else:
            self._reg_ids[ccid] = [cr]
        return cr

    def unregisterChaincodeEvent(self, cr):
        mylog('unregisterChaincodeEvent')
        self._reg_ids[cr.ccid].remove(cr)

        if not self._reg_ids[cr.ccid]:
            del self._reg_ids[cr.ccid]

    def have_registrations(self):
        mylog('have_registrations')
        return self._reg_nums != [] \
            or self._tx_ids != {} \
            or self._reg_ids != {}

    def _on_end_actions(self, event_reg, unregister_action, startstop_mode,
                        unregister, disconnect):
        mylog('_on_end_actions')
        if startstop_mode > 0:
            self._start_stop_action = {
                'event_reg': event_reg,
                'unregister': False,
                'disconnect': False
            }

            mylog(f'_on_end_actions')
            _end_register = True
            if unregister is not None:
                mylog(f'_on_end_actions 1')
                _end_register = unregister

            if _end_register and startstop_mode > 1:
                mylog(f'_on_end_actions 2')
                self._start_stop_action['unregister'] = unregister_action

            _end_disconnect = True
            if disconnect is not None:
                mylog(f'_on_end_actions 3')
                _end_disconnect = disconnect

            if _end_disconnect and startstop_mode > 1:
                mylog(f'_on_end_actions 4')
                self._start_stop_action['disconnect'] = True

    def check_replay_end(self):
        mylog('check_replay_end')
        if self._stop is not None:
            if isinstance(self._stop, int) and self._stop <= self._last_seen:
                self._ending_block_seen = True
                if self._start_stop_action:
                    if self._start_stop_action['unregister']:
                        self._start_stop_action['unregister']()
                    if self._start_stop_action['disconnect']:
                        mylog('check_replay_end disconnect')
                        self.disconnect()

    async def handle_stream(self, stream):
        mylog('handle_stream')
        async for event in stream:
            if event.WhichOneof('Type') in ('block', 'filtered_block'):
                mylog('handle_stream 1')
                self.connected = True

                if event.WhichOneof('Type') == 'block':
                    block = BlockDecoder().decode(
                        event.block.SerializeToString())
                    self._last_seen = block['header']['number']
                    mylog(f'handle_stream block {self._last_seen}')
                else:
                    mylog('handle_stream non-block')
                    block = FilteredBlockDecoder().decode(
                        event.filtered_block.SerializeToString())
                    self._last_seen = block['number']
                    mylog(f'handle_stream non-block {self._last_seen}')

                self._processBlockEvents(block)
                self._processTxEvents(block)
                self._processChaincodeEvents(block)

                self.check_replay_end()

            elif event.WhichOneof('Type') == 'status':
                mylog('handle_stream 4')
                if event.status == Status.Value('SUCCESS'):  # last block
                    mylog('handle_stream 5')
                    if self._ending_block_seen:
                        mylog('handle_stream 6')
                        _logger.debug(f'status received after last block '
                                      f'seen: {event.status}, block-num:'
                                      f' {self._last_seen}')
                    if self._ending_block_newest:
                        mylog('handle_stream disconnect _ending_block_newest')
                        self.disconnect()
                else:
                    mylog('handle_stream disconnect non_success')
                    self.disconnect()
            else:
                mylog('handle_stream 9')
                _logger.error(f'ChannelEventHub has received a unknown'
                              f' message type {event.WhichOneof("Type")}')

            try:
                s = stream._iterator
                mylog(f'handle_stream state.code={s._state.code} cancelled={s.cancelled()} running={s.running()} done={s.done()} is_active{s.is_active()} _is_complete={s._is_complete()} exception={s.exception()} time_remaining={s.time_remaining()}')
            except Exception as e:
                mylog(f'Cannot get stream status: {e}')

    def connect(self, filtered=True, start=None, stop=None,
                as_array=False,
                target=None, signed_event=None):
        mylog('connect')
        self._filtered = filtered
        self._as_array = as_array

        if target is not None:
            self._peer = target

        if signed_event is not None:
            self._signed_event = signed_event

        self.check_start_stop_connect(start, stop)

        self.stream = self._get_stream()

        return self.handle_stream(self.stream)

    def disconnect(self):
        mylog('disconnect')
        self.stream.cancel()
        self._start = None
        self._stop = None
        self._filtered = True
        self._peer = None
        self._requestor = None
        self._channel_name = None
        self._start_stop_action = {}
        self._start_stop_connect = False
        self._signed_event = None

        self._ending_block_seen = False
        self._ending_block_newest = False

        self.connected = False
