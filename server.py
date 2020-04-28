#! python3
from flask import Flask, escape, request, jsonify
from flask_socketio import SocketIO
from db import MIMSDatabase
import Crypto
import base64
import json
import threading
from collections import defaultdict

# Warning: This server is supposed to host this API along with a
# HTTPS enabled web server (like behind a Nginx reverse proxy)

app = Flask(__name__)
socketio = SocketIO(app)
db = None

# Key: client sid, Value: ClientInfo
connected_clients = {}

# Key: uuid, Value: set of ClientInfo
connected_users = defaultdict(set)

class ClientInfo:
    listening_uuid = None
    def __init__(self):
        # The uuid of the client subscribing
        self.listening_uuid = None
        # The number of new message checks remaining for the client
        # The number increments when new messages arrive, and decrements after checking
        # It defaults to 1 to always check for new messages
        self.scheduled_checks = 1
        # The thread lock for this client
        self.lock = threading.Lock()
    def schedule_check(self):
        with self.lock: self.scheduled_checks += 1
    def check_finished(self):
        with self.lock:
            if self.scheduled_checks > 0: self.scheduled_checks -= 1

@app.route('/')
def home():
    return "API endpoint for MIMS"

@app.route('/register_uuid', methods=['GET', 'POST'])
def register_uuid():
    response = db.register_new_keys (
        base64.b64decode(request.form['pks_pem']).decode('utf-8'),
        base64.b64decode(request.form['pke_pem']).decode('utf-8'),
        request.form['rsa_sig']
    )
    if response.successful:
        return jsonify(successful=True, message="Success", uuid=response.message)
    else:
        return jsonify(successful=False, message=response.message)

@app.route('/request_public_keys', methods=['GET', 'POST'])
def request_public_key():
    response = db.request_public_keys (
        request.form['requesting_uuid'],
        request.form['requester_uuid'],
        request.form['rsa_sig']
    )
    if response.successful:
        return jsonify(successful=True, message="Success", keys=response.requested_data)
    else:
        return jsonify(successful=False, message=response.message)

@app.route('/request_public_info', methods=['GET', 'POST'])
def request_public_info():
    response = db.request_public_info (
        request.form['requesting_uuid'],
        request.form['requester_uuid'],
        request.form['rsa_sig']
    )
    if response.successful:
        return jsonify(successful=True, message="Success", user_status=response.requested_data)
    else:
        return jsonify(successful=False, message=response.message)

@app.route('/send_messge', methods=['GET', 'POST'])
def send_message():
    response = db.send_message (
        request.form['recipient_uuid'],
        request.form['aes_key_encrypted'],
        request.form['message'],
        request.form['sender_uuid'],
        request.form['rsa_sig']
    )
    if response.successful:
        clients = connected_users.get(request.form['recipient_uuid'], None)
        if clients is not None:
            for client in clients.copy():
                client.schedule_check()
    return jsonify(successful=response.successful, message=response.message)

@app.route('/check_username_availablilty', methods=['GET', 'POST'])
def check_username_availablilty():
    return jsonify(successful=response.successful, message=db.check_username_exist(request.form['username']))

@app.route('/get_key_salt', methods=['GET', 'POST'])
def get_key_salt():
    response = db.get_key_salt (
        request.form['username']
    )
    if response.successful:
        return jsonify(successful=True, message="Success", salt=response.requested_data)
    else:
        return jsonify(successful=False, message=response.message)

@app.route('/upload_keys', methods=['GET', 'POST'])
def upload_keys():
    response = db.upload_identity (
        request.form['username'],
        request.form['keys'],
        request.form['retrieval_hash'],
        request.form['salt']
    )
    return jsonify(successful=response.successful, message=response.message);

@app.route('/download_keys', methods=['GET', 'POST'])
def download_keys():
    response = db.download_keys (
        request.form['username'],
        request.form['retrieval_hash']
    )
    if response.successful:
        return jsonify(successful=True, message="Success", keys=response.requested_data)
    else:
        return jsonify(successful=False, message=response.message)

@socketio.on('subscribe_messages')
def subscribe_messages(user_request):
    uuid = str(user_request['uuid'])
    rsa_sig = str(user_request['rsa_sig'])
    response = db.verify_request([uuid], uuid, rsa_sig)
    if not response.successful:
        return False, response.message
    sid = request.sid
    client = connected_clients.get(sid, None)
    if client is None:
        print(f"Client went missing during message subscription, aborting... (sid={sid} uuid={uuid})")
        socketio.disconnect()
    client.listening_uuid = uuid
    connected_users[uuid].add(client)
    print(f"Subscribing messages for client sid={sid} uuid={uuid}")
    on_client_subscribe_message(uuid)

def on_client_subscribe_message(uuid):
    sid = request.sid
    last_successful_retrieve = 0
    while (connected_clients.get(sid, ClientInfo()).listening_uuid == uuid):
        client = connected_clients.get(sid, None)
        if client is None or client.scheduled_checks <= 0:
            socketio.sleep(0.25)
            continue
        response = db.retrieve_messages(uuid, last_successful_retrieve)
        if not response.successful:
            print(f"Error retrieving messages for client sid={sid} uuid={uuid}, aborting...")
            socketio.disconnect()
        message_count = len(response.requested_data)
        if message_count > 0:
            print(f"{message_count} new messages arrived for uuid={uuid}, relaying it to client sid={sid}")
            socketio.emit('on_message_received',
                response.requested_data,
                room=sid,
                callback=lambda:on_client_received_message(uuid, response.message))
            client.check_finished()
            break # Pause message subscription until the client has successfully received the messages
        client.check_finished()

# Delete the messages received by client and contines to look for messages
def on_client_received_message(client_uuid, timestamp_received):
    db.delete_messages_older(uuid, timestamp_received)
    on_client_subscribe_message(uuid)

@socketio.on('connect')
def on_connect():
    connected_clients[request.sid] = ClientInfo()
    print(f"Client connected! sid={request.sid}")

@socketio.on('disconnect')
def on_disconnect():
    client = connected_clients.pop(request.sid, None)
    if client.listening_uuid is not None:
        connected_users.get(client.listening_uuid).discard(client)
    print(f"Client disconnected! sid={request.sid}, uuid={client.listening_uuid}")

if __name__ == '__main__':
    db = MIMSDatabase("db.sqlite")
    socketio.run(app, debug=True)
