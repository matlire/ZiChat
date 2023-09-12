# Import needed libraries and modules
import socket
import signal
import sys
import threading
from getpass import getpass
import random
import string
from cryptography.hazmat.primitives import serialization
import time

from config import *
from values import *
from crypto import Crypto
from colorfull import Colourfull

# Client class, inheritting from Crypto
class Client(Crypto, Colourfull):

    # Initing class 
    def __init__(self, ip : str, port : int) -> None:
        self.print_client()
        self.print_green()
        print("Initing...")
        self.ip = ip
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = ""
        chars = string.ascii_letters
        self.session_key = ''.join(random.choice(chars) for _ in range(SESSION_KEY_SIZE)) # Key, generated for every session and varifying this client
    
    # Connect
    def connect(self) -> [str, int]:
        try:
            # Establishing connection with server, generating and exchanging keys
            self.client.connect((self.ip, self.port))
            self.generate_key_pair()
            self.client.send(self.public_key)
            server_public_key = self.client.recv(PUBLIC_KEY_SIZE)
            server_public_key = serialization.load_pem_public_key(server_public_key)
            self.generate_secret(server_public_key)
            self.generate_mac_key()
            self.client.send(self.aes_encrypt(self.session_key.encode(), self.private_key).ljust(SESSION_KEY_ENC_SIZE) + self.generate_mac(self.session_key).ljust(SESSION_KEY_MAC_SIZE).encode())
            
            self.send_msg(SERVER_NAME, VERSION) # Version checking
            _, _, status = self.handle_data(self.client.recv(STATUS_SIZE))
            if status == STATUS_CODES.get("VERSCHECK"):
                self.print_client()
                self.print_red()
                print("Version mismatch! Please, update your client!")
                return "", 0

            self.print_yellow()
            print("Enter your data, you'll be automatacly registred if neccessary")
            self.print_green()

            # Username proccessing
            username = input("Enter your username: ")
            self.send_msg(username, username)
            _, _, status = self.handle_data(self.client.recv(STATUS_SIZE))
            if status == STATUS_CODES.get("INCUSERLEN"): # Incorrect size
                self.print_client()
                self.print_red()
                print("Username incorrect size")
                return "", 0
            elif status == STATUS_CODES.get("USERIN"): # Already online
                self.print_client()
                self.print_red()
                print("User already online")
                return "", 0
            elif status == STATUS_CODES.get("INCUSERF"): # Incorrect formatting
                self.print_client()
                self.print_red()
                print("Incorrect username format")
                return "", 0

            # Password processing
            password = getpass("Enter your password: ")
            self.send_msg(username, password)
            _, _, status = self.handle_data(self.client.recv(STATUS_SIZE))  
            if status == STATUS_CODES.get("INCPASSLEN"): # Incorrect size
                self.print_client()
                self.print_red()
                print("Password incorrect size")
                return "", 0
            elif status == STATUS_CODES.get("NOUSER"): # No such user => Register
                password = getpass("Repeat your password to register: ")
                self.send_msg(username, password)
                _, _, status = self.handle_data(self.client.recv(STATUS_SIZE))
                if status == STATUS_CODES.get("NOPASSMAT"): self.print_client(); self.print_red(); print("Passwords don't match"); return "", 0 # Passwords don't match
                elif status == STATUS_CODES.get("INCPASSLEN"): self.print_client(); self.print_red(); print("Password incorrect size"); return "", 0 # Incorrect size
            elif status == STATUS_CODES.get("INCPASS"): self.print_client(); self.print_red(); print("Incorrect password"); return "", 0 # Incorrect password
            elif status == STATUS_CODES.get("INCPASSF"): self.print_client(); self.print_red(); print("Incorrect password format"); return "", 0 # Incorrect format
            
            self.username = username
                
        except Exception as error: # If any errors
            return f"[CLIENT] {error}", 0
        return f"Connected succesfully to {SERVER_NAME} with username {self.username}", STATUS_CODES.get("SUCCESS") # If no errors

    # Client's loop
    def loop(self) -> int:
        self.print_cyan()
        self.thread = threading.Thread(target=self.get_data_loop, daemon=True) # Another thread for getting data
        self.thread.start()
        time.sleep(0.1)
        while True: # Send data loop
            if self.thread.is_alive() == False:
                break
            self.print_cyan()
            msg = input()
            if msg == "":
                break
            try:
                recepient, msg = msg.split(":", 1) # Split to get recepient and message
                if msg == COMMANDS.get("HELP"): # Help message executed locally
                    print(HELP_MSG)
                    continue
                if msg == COMMANDS.get("DISCONNECT"): # Disconnect message executed locally
                    self.disconnect()
                if recepient == "SERVER" or recepient == "": # Auto replace recepient to server
                    recepient = SERVER_NAME
            except ValueError: # Splitting failed
                self.print_client()
                self.print_red()
                print("Enter message in correct format: RECEPIENT:MESSAGE")
                continue
            if len(msg) > MSG_MAX_SIZE: # Too long msg, executed locally and throws error on server side
                self.print_client()
                self.print_red()
                print("Too long message!")
                continue
            self.send_msg(recepient, msg)
        self.disconnect() # Disconnect on loop ends
        return 0
    
    # Disconnect client
    def disconnect(self) -> None:
        self.print_client()
        self.print_red()
        print(f"Disconnected from {SERVER_NAME}")
        sys.exit(0)
        return
    
    # Send message method
    def send_msg(self, username : str, data : str) -> None:
        data = str(data)
        usern = self.username.encode().ljust(USERNAME_SIZE_TO)
        username = username.encode().ljust(USERNAME_SIZE_TO)
        mac = self.generate_mac(data)
        data = data.encode()
        data = usern + username + data
        data = self.aes_encrypt(data, self.private_key)
        session_key = self.aes_encrypt(self.session_key.encode(), self.private_key)
        msg_len = len(data)
        data = msg_len.to_bytes(4, byteorder='big') + data + session_key + mac.encode()
        self.client.send(data)

    # Handle got data method
    def handle_data(self, data : bytes) -> [str, str, str]:
        msg_len = data[:4]
        msg_len = int.from_bytes(msg_len, byteorder='big')
        f_msg = data[4:4+msg_len]
        _session_key = data[4+msg_len:4+msg_len+SESSION_KEY_ENC_SIZE]
        mac = data[4+msg_len+SESSION_KEY_ENC_SIZE:]
        _session_key = self.aes_decrypt(_session_key, self.private_key)
        f_msg = self.aes_decrypt(f_msg, self.private_key)
        sender = f_msg[:USERNAME_SIZE_TO].strip()
        recepient = f_msg[USERNAME_SIZE_TO:USERNAME_SIZE_TO * 2].strip()   
        msg = f_msg[USERNAME_SIZE_TO * 2:]
        if (self.verify_mac(msg, mac)) and (_session_key == self.session_key): # Verifying if message was corrupted
            return sender, recepient, msg
        else:
            return "[Corrupted]", "[Corrupted]", "Corrupted"

    # Get message loop (in another thread)
    def get_data_loop(self) -> None:
        data = b""
        while True:
            try:
                data = self.client.recv(4340) # Recive data
                if not data:
                    break
                try:
                    sender, recepient, data = self.handle_data(data) # Split got data
                    if sender == SERVER_NAME:
                        self.print_client_from(sender)
                        self.print_red()
                        if data == SERVER_KILL_CMD: # If server killed
                            print(f"Server went offline. Try again later...")
                            self.print_cyan()
                            break
                        if data == STATUS_CODES.get("CHECK"): self.print_cyan(); continue # If pinged client
                        if data == STATUS_CODES.get("INVARGS"): # Invalid arguments
                            print("Invalid arguments!")
                            self.print_cyan()
                            continue
                        if data == STATUS_CODES.get("FRREQSNT"): # Friend request already sent
                            print("Friends request already sent!")
                            self.print_cyan()
                            continue
                        if data == STATUS_CODES.get("NOTFRDS"): # You are not friends
                            print("You are not friends!")
                            self.print_cyan()
                            continue
                        if data == STATUS_CODES.get("NOUSER"): # No such user
                            print("No such user!")
                            self.print_cyan()
                            continue
                        if data == STATUS_CODES.get("SUCCESS"): # Success on doing sth
                            self.print_green()
                            print("Success!")
                            self.print_cyan()
                            continue
                        if data == STATUS_CODES.get("INCPASS"): # Incorrect password on :change
                            print("Old password is incorrect!")
                            self.print_cyan()
                            continue
                        if data == STATUS_CODES.get("INCPASSLEN"): # Incorrect password size
                            print("Password incorrect size!")
                            self.print_cyan()
                            continue
                        if data == STATUS_CODES.get("INCPASSF"): # Incorrect password size
                            print("Password incorrect format!")
                            self.print_cyan()
                            continue
                        try:
                            cr_data = data[2:-1]
                            _type = cr_data[:3]
                            cr_data = cr_data[3:]
                            cr_data = cr_data.split()
                        except ValueError:
                            print(data)
                            self.print_cyan()
                            continue
                        if _type == "frd": # If friends were requested
                            self.print_cyan()
                            print("Friends: ")
                            for i in range(len(cr_data)):
                                if cr_data[i] == "None":
                                    print("You have no friends!")
                                    self.print_cyan()
                                    break
                                if (cr_data[i] in WORD_BLACKLIST) or any(char in (SYMBOL_BLACKLIST) for char in cr_data[i]): print(f"{cr_data[i]}")
                                else: print(f"- {cr_data[i]}")
                        elif _type == "req": # If requests were requested
                            self.print_cyan()
                            print("Friends requests: ")
                            for i in range(len(cr_data)):
                                if cr_data[i] == "None":
                                    print("You have no friends requests!")
                                    self.print_cyan()
                                    break
                                if (cr_data[i] in WORD_BLACKLIST) or any(char in (SYMBOL_BLACKLIST) for char in cr_data[i]): print(f"{cr_data[i]}")
                                else: print(f"- {cr_data[i]}")
                        else:
                            print(data)
                            self.print_cyan()
                            continue
                        self.print_cyan()
                        continue
                except ValueError:
                    continue
            except ConnectionResetError or ConnectionAbortedError: # If connecyion reseted
                self.print_client()
                self.print_red()
                print(f"Server went offline. Try again later...")
                break
            self.print_client_from(sender)
            self.print_cyan()
            print(f"{data}")
        self.disconnect()

# Exit programm handler
def exit_handler(signal, frame) -> None:
    Colourfull().print_client()
    Colourfull().print_red()
    print("Unexpectely proccess was finished.")
    sys.exit(0)

# If script was started
if __name__ == "__main__":
    signal.signal(signal.SIGINT, exit_handler) # Binding Ctrl+C event

    # Starting client
    client = Client(IP, PORT)
    msg, status = client.connect()
    if status == STATUS_CODES.get("FAILHOST"):
        Colourfull().print_red()
    else:
        Colourfull().print_client()
        Colourfull().print_yellow()
    print(msg)
    if status:
        status = client.loop()
