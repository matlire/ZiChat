# Import needed libraries and modules
import socket
import threading
import sys
from cryptography.hazmat.primitives import serialization
import signal
import string
import time
import shutil

from config import *
from values import *
from crypto import Crypto
from db import DB
from colorfull import Colourfull

# Server class
class Server(Colourfull):

    # Initing class 
    def __init__(self, ip : str, port : int) -> None:
        self.ip = ip
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.active_users = {} # Online users, format: "Username": [ip, session_key, socket_object, crypto_object, chatting_with]

    # Host server
    def host(self) -> [str, int]:
        try:
            self.server.bind((self.ip, self.port))
        except Exception as error: # If any errors
            return f"{error}", STATUS_CODES.get("FAILHOST")
        return f"Succesfully hosted on {self.ip}:{self.port}", STATUS_CODES.get("SUCCESS") # If no errors

    # Server loop
    def loop(self) -> None:
        thread = threading.Thread(target=self._input, daemon=True) # New thread for every client
        thread.start()
        self.server.listen(MAX_CLIENTS)
        while True:
            try:
                client_socket, client_address = self.server.accept() # Accept new connection
                thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True) # New thread for every client
                thread.start()
            except KeyboardInterrupt:
                break
        self.close()

    def _input(self) -> None: # Input commands on server
        cmd = input()
        if cmd == SERVER_KILL_CMD:
            self.close()
        if cmd == BACKUP_CMD:
            shutil.copyfile(DB_NAME, DB_NAME + "-copy")

    # Handle client
    def handle_client(self, client_socket : socket.socket, client_address : tuple) -> None:
        try:
            crypto = Crypto() # New Crypto object for every client
            crypto.generate_key_pair() # Establishing connection with client, generating and exchanging keys
            client_public_key = client_socket.recv(PUBLIC_KEY_SIZE)
            client_public_key = serialization.load_pem_public_key(client_public_key)
            client_socket.send(crypto.public_key)
            crypto.generate_secret(client_public_key)
            crypto.generate_mac_key()
            data = client_socket.recv(SESSION_MSG_SIZE)
            session_key = data[:SESSION_KEY_ENC_SIZE].strip()
            try:
                session_key = crypto.aes_decrypt(session_key, crypto.private_key)
            except ValueError:
                return
            mac = data[SESSION_KEY_ENC_SIZE:].strip()
            if crypto.verify_mac(session_key, mac) == False: # Verifying if client's data wasn't corrupted
                self.print_server()
                self.print_red()
                print(f"{client_address} - Mac verifecation failed; Disconnected")
                return

            _, _, client_version = self.handle_data(crypto, client_socket.recv(STATUS_SIZE), session_key) # Version checking
            if client_version != VERSION: self.send_msg(crypto, SERVER_NAME, "CLIENT", STATUS_CODES.get("VERSCHECK"), session_key, 0, client_socket); return
            else: self.send_msg(crypto, SERVER_NAME, "CLIENT", STATUS_CODES.get("SUCCESS"), session_key, 0, client_socket)

            # Proccessing username
            username = ""
            try:
                username = client_socket.recv(LOG_REG_DATA_SIZE) 
                _, _, username = self.handle_data(crypto, username, session_key)
            except ValueError: # Incorrect username format
                self.send_msg(crypto, SERVER_NAME, username, STATUS_CODES.get("INCUSERF"), session_key, 0, client_socket)
                self.print_server()
                self.print_red()
                print(f"{username} - Username incorrect format; Disconnected")
                return
            if len(username) < USERNAME_SIZE_FROM or len(username) > USERNAME_SIZE_TO or username == "Corrupted": # Incorrect username size
                self.send_msg(crypto, SERVER_NAME, username, STATUS_CODES.get("INCUSERLEN"), session_key, 0, client_socket)
                self.print_server()
                self.print_red()
                print(f"{username} - Username incorrect size; Disconnected")
                return
            if username in self.active_users: # User already online
                if self.send_msg(crypto, SERVER_NAME, username, STATUS_CODES.get("CHECK"), session_key): # Check if another client with the same username online
                    self.send_msg(crypto, SERVER_NAME, username, STATUS_CODES.get("USERIN"), session_key, 0, client_socket)
                    self.print_server()
                    self.print_red()
                    print(f"{username} - User already online; Disconnected")
                    return
                self.print_server()
                self.print_red()
                print(f"{username} - User lost connection")
            if any(char in (SYMBOL_BLACKLIST) for char in username) or username in WORD_BLACKLIST: # If username contains blacklist symbols/words
                self.send_msg(crypto, SERVER_NAME, username, STATUS_CODES.get("INCUSERF"), session_key, 0, client_socket)
                self.print_server() 
                self.print_red()
                print(f"{username} - Username incorrect format; Disconnected")
                return

            self.active_users[username] = [client_address, session_key, client_socket, crypto, SERVER_NAME] # Add user to active users
            self.send_msg(crypto, SERVER_NAME, username, STATUS_CODES.get("SUCCESS"), session_key)
            
            # Proccessing password
            try:
                password = client_socket.recv(LOG_REG_DATA_SIZE)
                _, _, password = self.handle_data(crypto, password, session_key)
            except ValueError: # Incorrect username format
                self.send_msg(crypto, SERVER_NAME, username, STATUS_CODES.get("INCPASSF"), session_key, 0, client_socket)
                self.print_server()
                self.print_red()
                print(f"{username} - Password incorrect format; Disconnected")
                return
            if len(password) < PASSWORD_SIZE_FROM or len(password) > PASSWORD_SIZE_TO: # Incorrect password size
                self.send_msg(crypto, SERVER_NAME, username, STATUS_CODES.get("INCPASSLEN"), session_key)
                self.active_users.pop(username)
                self.print_server()
                self.print_red()
                print(f"{username} - Password incorrect size; Disconnected")
                return
            if any(char in (SYMBOL_BLACKLIST) for char in password) or username == "None" or password == "Corrupted": # Incorrecct password format
                self.send_msg(crypto, SERVER_NAME, username, STATUS_CODES.get("INCPASSF"), session_key, 0, client_socket)
                self.print_server()
                self.print_red()
                print(f"{username} - Password incorrect format; Disconnected")
                return

            db = DB() # Connect to db
            status = db.verify_username(username)
            if status == STATUS_CODES.get("SUCCESS"): # Logging in to db
                status = db.login(username)
                if status != STATUS_CODES.get("NOUSER"):
                    status = crypto.check_data(password, status)
                    self.send_msg(crypto, SERVER_NAME, username, status, session_key)
                    if status == STATUS_CODES.get("SUCCESS"): # Check password
                        db.update_user_info(username)
                    else:
                        db.disconnect()
                        self.active_users.pop(username)
                        self.print_server()
                        self.print_red()
                        print(f"{username} - Passwords don't match; Disconnected")
                        return
            else: # Registering user
                password = crypto.hash_data(password)
                self.send_msg(crypto, SERVER_NAME, username, status, session_key)
                new_password = client_socket.recv(LOG_REG_DATA_SIZE)
                _, _, new_password = self.handle_data(crypto, new_password, session_key) # Asking for repeating password & same checks for it
                if len(new_password) < USERNAME_SIZE_FROM or len(new_password) > USERNAME_SIZE_TO or new_password == "Corrupted":
                    self.send_msg(crypto, SERVER_NAME, username, STATUS_CODES.get("INCPASSLEN"), session_key)
                    self.active_users.pop(username)
                    self.print_server()
                    self.print_red()
                    print(f"{username} - Password incorrect size; Disconnected")
                    return
                if crypto.check_data(new_password, password): status = db.register_user(username, password) # If password are the same
                else: # If password are not the same
                    status = STATUS_CODES.get("NOPASSMAT")
                    self.send_msg(crypto, SERVER_NAME, username, status, session_key)
                    db.disconnect()
                    self.active_users.pop(username)
                    self.print_server()
                    self.print_red()
                    print(f"{username} - Passwords don't match; Disconnected")
                    return
                self.send_msg(crypto, SERVER_NAME, username, status, session_key)

            self.print_server()
            self.print_yellow()
            print(f"Established connection with {username}")
            shutil.copyfile(DB_NAME, DB_NAME + "-copy")

            self.send_msg(crypto, SERVER_NAME, username, "Don't forget to checkout http://XXXXXX and update your client! Type ':help' to get help!", session_key)

            # Interacting with client loop
            while True:
                try:
                    data = client_socket.recv(4340) # Getting data from client
                    if not data:
                        break
                    db.update_user_info(username)
                    # Resending got data to needed user
                    sender, recepient, data = self.handle_data(crypto, data, session_key)
                    if recepient == SERVER_NAME:
                        if data == COMMANDS.get("DISCONNECT"): # :dis command
                            self.print_server()
                            self.print_red()
                            print(f"{username} - connection closed")
                            self.active_users.pop(username)
                            break
                        if data == COMMANDS.get("FRIENDS"): # :friends command
                            friends = db.get_all_friends(username)
                            all_friends = b'frd'
                            if friends: all_friends += b''.join(friends[i].encode().ljust(USERNAME_SIZE_TO) for i in range(len(friends)))
                            else: all_friends += b'None'
                            self.send_msg(crypto, SERVER_NAME, sender, all_friends, self.active_users.get(sender)[1])
                            self.print_server_from_to(sender, recepient)
                            self.print_cyan()
                            print("friends")
                        elif data == COMMANDS.get("REQUESTS"): # :requests command
                            requests = db.get_all_requests(username)
                            all_requests = b'req'
                            if requests: all_requests += b''.join(requests[i].encode().ljust(USERNAME_SIZE_TO) for i in range(len(requests)))
                            else: all_requests += b'None'
                            self.send_msg(crypto, SERVER_NAME, sender, all_requests, self.active_users.get(sender)[1])
                            self.print_server_from_to(sender, recepient)
                            self.print_cyan()
                            print("requests")
                        else: # If command with arguments
                            try:
                                data = data.split()
                            except:
                                self.send_msg(crypto, SERVER_NAME, sender, STATUS_CODES.get("INVARGS"), session_key)
                                continue
                            if len(data) < 2:
                                self.send_msg(crypto, SERVER_NAME, sender, STATUS_CODES.get("INVARGS"), session_key)
                                continue
                            cmd = data[0]
                            arg = data[1] # Getting arguments
                            if sender == arg:
                                self.send_msg(crypto, SERVER_NAME, sender, STATUS_CODES.get("INVARGS"), session_key)
                                continue

                            if cmd == COMMANDS.get("ADD"): # :add [username] command
                                if db.verify_username(arg) == STATUS_CODES.get("NOUSER"):
                                    self.send_msg(crypto, SERVER_NAME, sender, STATUS_CODES.get("NOUSER"), session_key)
                                    continue
                                status = db.new_friend_request(sender, arg)
                                self.send_msg(crypto, SERVER_NAME, sender, status, session_key)
                            if cmd == COMMANDS.get("REMOVE"): # :remove [username] command
                                if db.verify_username(arg) == STATUS_CODES.get("NOUSER"):
                                    self.send_msg(crypto, SERVER_NAME, sender, STATUS_CODES.get("NOUSER"), session_key)
                                    continue
                                status = db.delete_friend(sender, arg)
                                self.send_msg(crypto, SERVER_NAME, sender, status, session_key)
                            if cmd == COMMANDS.get("ACCEPT"): # :accept [username] command
                                if db.verify_username(arg) == STATUS_CODES.get("NOUSER"):
                                    self.send_msg(crypto, SERVER_NAME, sender, STATUS_CODES.get("NOUSER"), session_key)
                                    continue
                                status = db.accept_friend_requets(arg, sender)
                                self.send_msg(crypto, SERVER_NAME, sender, status, session_key)
                            if cmd == COMMANDS.get("DECLINE"): # :decline [username] command
                                if db.verify_username(arg) == STATUS_CODES.get("NOUSER"):
                                    self.send_msg(crypto, SERVER_NAME, sender, STATUS_CODES.get("NOUSER"), session_key)
                                    continue
                                db.decline_friend_request(arg, sender)
                                db.decline_friend_request(sender, arg)
                                self.send_msg(crypto, SERVER_NAME, sender, STATUS_CODES.get("SUCCESS"), session_key)
                            if cmd == COMMANDS.get("LOAD"): # :load [username] command
                                if db.verify_username(arg) == STATUS_CODES.get("NOUSER"):
                                    self.send_msg(crypto, SERVER_NAME, sender, STATUS_CODES.get("NOUSER"), session_key)
                                    continue
                                data, invertings = self.get_messages(db, crypto, sender, arg)
                                j = 0
                                for i in data:
                                    if invertings[j] == 0: self.send_msg(crypto, "YOU", sender, i, session_key)
                                    else: self.send_msg(crypto, arg, sender, i, session_key)
                                    j += 1
                                    time.sleep(0.01)
                            if cmd == COMMANDS.get("CHANGE"): # :change [old_password] [new_password] command
                                if len(data) == 3:
                                    arg2 = data[2]
                                    if len(arg2) < PASSWORD_SIZE_FROM or len(arg2) > PASSWORD_SIZE_TO or arg2 == "Corrupted":
                                        self.send_msg(crypto, SERVER_NAME, sender, STATUS_CODES.get("INCPASSLEN"), session_key)
                                    if any(char in (SYMBOL_BLACKLIST) for char in arg2):
                                        self.send_msg(crypto, SERVER_NAME, sender, STATUS_CODES.get("INCPASSF"), session_key)
                                    status = db.login(sender)
                                    if status != STATUS_CODES.get("NOUSER"):
                                        status = crypto.check_data(arg, status)
                                        if status != STATUS_CODES.get("SUCCESS"): self.send_msg(crypto, SERVER_NAME, sender, status, session_key)
                                        else:
                                            db.update_password(sender, crypto.hash_data(arg2))
                                            self.send_msg(crypto, SERVER_NAME, sender, STATUS_CODES.get("SUCCESS"), session_key)
                                else: self.send_msg(crypto, SERVER_NAME, sender, STATUS_CODES.get("INVARGS"), session_key)

                        continue

                    if db.verify_username(recepient) == STATUS_CODES.get("NOUSER"): # If requested recepient and sender are not friends
                        self.send_msg(crypto, SERVER_NAME, sender, STATUS_CODES.get("NOTFRDS"), session_key)
                        continue
                    if db.check_friends(sender, recepient):
                        to_user = self.active_users.get(recepient)
                        if to_user:
                            to_session_key = to_user[1]
                            to_crypto = to_user[3]
                            if db.check_friends(sender, recepient):
                                self.send_msg(to_crypto, sender, recepient, data, to_session_key)
                                
                                self.print_server_from_to(sender, recepient)
                                self.print_cyan()
                                print("Message") 
                        self.new_message(db, crypto, sender, recepient, data)
                    else:
                        self.send_msg(crypto, SERVER_NAME, sender, STATUS_CODES.get("NOTFRDS"), session_key)
                                
                        self.print_server_from_to(SERVER_NAME, sender)
                        self.print_cyan()
                        print("Not friends")
                except ValueError as er:
                    self.print_server()
                    self.print_red()
                    print(f"{username} - connection closed")
                    self.active_users.pop(username)
                    print(er)
                    break
            db.disconnect()
            client_socket.close()
        except ConnectionResetError: # If client closed connection
            self.print_server()
            self.print_red()
            print(f"{username} - connection closed")
            client_socket.close()
            self.active_users.pop(username)

    # Add new message
    def new_message(self, db : DB, crypto : Crypto, sender : str, recepient : str, data : bytes) -> None:
        key = crypto.generate_one_time_key(data)
        data = crypto.aes_encrypt(data.encode(), key)
        key = crypto.aes_encrypt(key, DB_MSG_ENC_KEY)
        db.new_message(sender, recepient, data, key)

    # Get all messages with user
    def get_messages(self, db : DB, crypto : Crypto, sender : str, recepient : str) -> None:
        keys, data, invertings = db.get_messages(sender, recepient)
        if keys == None: return ["Data corrupted"]
        de_data, j = [], 0
        for i in keys:
            key = crypto.aes_decrypt(i[0], DB_MSG_ENC_KEY)
            de_data.append(crypto.aes_decrypt(data[j][0], key))
            j += 1
        return de_data, invertings # Return decrypted data, invertings (sender & recepient changed)

    # Shutdown server
    def close(self) -> None:
        for i, key in enumerate(self.active_users): # Disconnect all clients
            client = self.active_users.get(key)
            self.send_msg(client[3], SERVER_NAME, key, SERVER_KILL_CMD, client[1])
            client[2].close()
        self.active_users.clear()
        self.server.close()
        self.print_server()
        self.print_red()
        print("Shutted down.")
        sys.exit(0)
    
    # Send message method
    def send_msg(self, crypto : Crypto, sender : str, recepient : str, data : str, to_session_key : str, use_active_users=1, client=None) -> int:
        try:
            data = str(data)
            usern = sender.encode().ljust(USERNAME_SIZE_TO)
            username = recepient.encode().ljust(USERNAME_SIZE_TO)
            mac = crypto.generate_mac(data)
            data = data.encode()
            data = usern + username + data
            data = crypto.aes_encrypt(data, crypto.private_key)
            to_session_key = crypto.aes_encrypt(to_session_key.encode(), crypto.private_key)
            msg_len = len(data)
            data = msg_len.to_bytes(4, byteorder='big') + data + to_session_key + mac.encode()
            if use_active_users:
                client = self.active_users.get(recepient)[2]
            client.send(data)
            return STATUS_CODES.get("SUCCESS")
        except OSError:
            self.active_users.pop(recepient)
            return 0

    # Handle got data method
    def handle_data(self, crypto : Crypto, data : bytes, session_key : str) -> [str, str, str]:
        try:
            msg_len = data[:4]
            msg_len = int.from_bytes(msg_len, byteorder='big')
            f_msg = data[4:4+msg_len]
            _session_key = data[4+msg_len:4+msg_len+SESSION_KEY_ENC_SIZE]
            mac = data[4+msg_len+SESSION_KEY_ENC_SIZE:]
            _session_key = crypto.aes_decrypt(_session_key, crypto.private_key)
            f_msg = crypto.aes_decrypt(f_msg, crypto.private_key)
            sender = f_msg[:USERNAME_SIZE_TO].strip()
            recepient = f_msg[USERNAME_SIZE_TO:USERNAME_SIZE_TO * 2].strip()   
            msg = f_msg[USERNAME_SIZE_TO * 2:]
            if (crypto.verify_mac(msg, mac)) and (_session_key == session_key):
                return sender, recepient, msg
            else:
                return "[Corrupted]", "[Corrupted]", "Corrupted"
        except ValueError:
            return "[Corrupted]", "[Corrupted]", "Corrupted"

# Exit programm handler
def exit_handler(signal, frame) -> None:
    Colourfull().print_server()
    Colourfull().print_red()
    print("Unexpectely proccess was finished.")
    sys.exit(0)

# If script was started
if __name__ == "__main__":
    signal.signal(signal.SIGINT, exit_handler) # Binding Ctrl+C event
    
    # Starting server
    server = Server(IP, PORT)
    msg, status = server.host()
    if status == STATUS_CODES.get("FAILHOST"):
        Colourfull().print_red()
    else:
        Colourfull().print_server()
        Colourfull().print_green()
    print(msg)
    if status == STATUS_CODES.get("SUCCESS"):
        server.loop()
