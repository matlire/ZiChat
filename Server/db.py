# Import needed libraries and modules
import sqlite3 as sq
from datetime import datetime

from values import *
from crypto import Crypto

# DB class
class DB:

    # Initing class 
    def __init__(self):
        self.db = sq.connect(DB_NAME)
        self.curs = self.db.cursor()
    # Disconnect from db
    def disconnect(self) -> None:
        self.db.commit()
        self.curs.close()
        self.db.close()
    
    # Register user in db
    def register_user(self, username : str, password : bytes) -> str:
        self.curs.execute("INSERT INTO Users(username, password, last_activity) VALUES (?, ?, ?)", (username, password, datetime.now()))
        self.db.commit()
        return STATUS_CODES.get("SUCCESS")
    # Login (returns username's password)
    def login(self, username : str) -> [str, bytes]:
        db_password = self.curs.execute("SELECT password FROM Users WHERE username=?", (username, )).fetchone()[0]
        if db_password == None: return STATUS_CODES.get("NOUSER")
        return db_password
    # Update user info in db
    def update_user_info(self, username : str) -> None:
        self.curs.execute("UPDATE Users SET last_activity=? WHERE username=?", (datetime.now(), username))
        self.db.commit()
    # Verifying user's password on login
    def verify_password(self, username : str, password : bytes) -> bool:
        passwd = self.curs.execute("SELECT password FROM Users WHERE username=?", (username, )).fetchone()[0]
        if passwd == password: return True # If given password == password from db
        return False
    # Verifying user's username
    def verify_username(self, username : str) -> str:
        usern = self.curs.execute("SELECT * FROM Users WHERE username = ?", (username, )).fetchone()
        if usern == None: return STATUS_CODES.get("NOUSER") # If no such username
        return STATUS_CODES.get("SUCCESS")
    # Update password
    def update_password(self, username : str, password : bytes) -> None:
        self.curs.execute("UPDATE Users SET password=? WHERE username=?", (password, username))
        self.db.commit()

    # Add new message
    def new_message(self, sender : str, recepient : str, message : bytes, key : bytes) -> None:
        now_history_size = len(self.curs.execute("SELECT id FROM Messages WHERE (sender=? AND recepient=?) OR (sender=? AND recepient=?) ORDER BY id", (sender, recepient, recepient, sender)).fetchall())
        while now_history_size > HISTORY_SIZE: # We need to delete old messages
            now_history_size = len(self.curs.execute("SELECT id FROM Messages WHERE (sender=? AND recepient=?) OR (sender=? AND recepient=?) ORDER BY id", (sender, recepient, recepient, sender)).fetchall())
            max_id = self.curs.execute("SELECT id FROM Messages WHERE (sender=? AND recepient=?) OR (sender=? AND recepient=?) ORDER BY id", (sender, recepient, recepient, sender)).fetchone()[0]
            self.curs.execute("DELETE FROM Messages WHERE id=?", (int(max_id),))
        self.curs.execute("INSERT INTO Messages (sender, recepient, message, timestamp, key) VALUES (?, ?, ?, ?, ?)", (sender, recepient, message, datetime.now(), key))
        self.db.commit()
    # Get messages from sender/recepient to sender/recepient
    def get_messages(self, sender : str, recepient : str) -> [[], [], []]:
        keys = self.curs.execute("SELECT key FROM Messages WHERE (sender=? AND recepient=?) OR (recepient=? AND sender=?) ORDER BY id", (sender, recepient, sender, recepient)).fetchall()
        data = self.curs.execute("SELECT message FROM Messages WHERE (sender=? AND recepient=?) OR (recepient=? AND sender=?) ORDER BY id", (sender, recepient, sender, recepient)).fetchall()
        if len(keys) != len(data): return
        j, invertings = 0, []
        for i in keys:
            _sender = self.curs.execute("SELECT sender FROM Messages WHERE message=? AND key=?", (data[j][0], i[0])).fetchone()[0]
            if _sender == sender: invertings.append(0)
            else: invertings.append(1)
            j += 1
        return keys, data, invertings # Return keys for messages, messages, inverting (if sender & recepient are changed)
    # Recrypt message
    def recrypt_message(self, _id : int, data : bytes, key : bytes) -> None:
        self.curs.execute("UPDATE Messages SET message=? WHERE id=?", (data, _id))
        self.curs.execute("UPDATE Messages SET key=? WHERE id=?", (key, _id))
        self.db.commit()
    
    # Create new friends request
    def new_friend_request(self, sender : str, recepient : str) -> str:
        is_sent_a = self.curs.execute("SELECT accepted FROM Friends WHERE sender=? AND recepient=?", (sender, recepient)).fetchone()
        is_sent_b = self.curs.execute("SELECT accepted FROM Friends WHERE recepient=? AND sender=?", (sender, recepient)).fetchone()
        if is_sent_a or is_sent_b: return STATUS_CODES.get("FRREQSNT") # If friend request already exist
        self.curs.execute("INSERT INTO Friends (sender, recepient, timestamp, accepted) VALUES (?, ?, ?, ?)", (sender, recepient, datetime.now(), 0))
        self.db.commit()
        return STATUS_CODES.get("SUCCESS")
    # Accept friend request
    def accept_friend_requets(self, sender : str, recepient : str) -> str:
        status = self.curs.execute("SELECT accepted FROM Friends WHERE sender=? AND recepient=?", (sender, recepient)).fetchall()
        if status: # If friend request exists
            self.curs.execute("UPDATE Friends SET accepted=? WHERE sender=? AND recepient=?", (1, sender, recepient))
            self.db.commit()
            return STATUS_CODES.get("SUCCESS")
        return STATUS_CODES.get("INVARGS")
    # Decline friend request
    def decline_friend_request(self, sender : str, recepient : str) -> None:
        self.curs.execute("DELETE FROM Friends WHERE sender=? AND recepient=? AND accepted=?", (sender, recepient, 0))
        self.db.commit()
    # Get all username's friends
    def get_all_friends(self, username : str) -> []:
        as_sender, as_recepient, all_friends = (), (), []
        try:
            as_sender = self.curs.execute("SELECT recepient FROM Friends WHERE sender=? AND accepted=?", (username, 1)).fetchall()
        except IndexError: pass
        try:
            as_recepient = self.curs.execute("SELECT sender FROM Friends WHERE recepient=? AND accepted=?", (username, 1)).fetchall()
        except IndexError: pass
    
        friends = as_sender + as_recepient # friends = accepted friend requests as sender + accepted friend requests as recepient
        for i in range(len(friends)):
            all_friends.append(friends[i][0])
        return all_friends
        # Get all username's friends requests
    def get_all_requests(self, username : str) -> []:
        as_sender, as_recepient, all_requests = (), (), ["OUTGOING:"]
        try:
            as_sender = self.curs.execute("SELECT recepient FROM Friends WHERE sender=? AND accepted=?", (username, 0)).fetchall()
        except IndexError: pass
        try:
            as_recepient = self.curs.execute("SELECT sender FROM Friends WHERE recepient=? AND accepted=?", (username, 0)).fetchall()
        except IndexError: pass

        if len(as_sender) == 0: # If no requests as sender
            all_requests.append("-----")
        for i in range(len(as_sender)):
            all_requests.append(as_sender[i][0])
        all_requests.append("INGOING:")
        if len(as_recepient) == 0:# If no requests as recepient
            all_requests.append("-----")
        for i in range(len(as_recepient)):
            all_requests.append(as_recepient[i][0])
        return all_requests # requests = not accepted friend requests as sender + not accepted friend requests as recepient
    # Check if user A and user B are friends
    def check_friends(self, user_a : str, user_b : str) -> bool:
        are_friends = 0
        try:
            are_friends += self.curs.execute("SELECT accepted FROM Friends WHERE sender=? AND recepient=?", (user_a, user_b)).fetchone()[0] # are friends as sender
        except TypeError: pass
        try:
            are_friends += self.curs.execute("SELECT accepted FROM Friends WHERE sender=? AND recepient=?", (user_b, user_a)).fetchone()[0] # are friends as recepient
        except TypeError: pass
        if are_friends > 0: return 1
        return 0
    # Delete friend
    def delete_friend(self, user_a : str, user_b : str) -> str:
        status = STATUS_CODES.get("NOTFRDS")
        try:
            if self.curs.execute("SELECT accepted FROM Friends WHERE (sender=? AND recepient=?) OR (sender=? AND recepient=?)", (user_a, user_b, user_b, user_a)).fetchone()[0] == 1: # if such accepted frien request exists
                self.curs.execute("DELETE FROM Friends WHERE (sender=? AND recepient=? AND accepted=?) OR (sender=? AND recepient=? AND accepted=?)", (user_a, user_b, 1, user_b, user_a, 1))
                status = STATUS_CODES.get("SUCCESS")
        except IndexError: pass
        self.db.commit()
        return status

    # Clear all db
    def clear_all(self) -> None:
        self.curs.execute("DELETE FROM Users")
        self.curs.execute("DELETE FROM Messages")
        self.curs.execute("DELETE FROM Friends")
        self.curs.execute("DELETE FROM sqlite_sequence")
        self.db.commit() # Clear all data from all tables
    # Recrypt all db
    def recrypt(self, old_key : bytes, new_key : bytes) -> None:
        crypto = Crypto()
        for i in range(len(self.curs.execute("SELECT id FROM Messages").fetchall())): # For i in all messages
            _id = self.curs.execute("SELECT id FROM Messages").fetchall()[i][0]
            data = self.curs.execute("SELECT message FROM Messages WHERE id=?", (_id,)).fetchone()[0]
            key = self.curs.execute("SELECT key FROM Messages WHERE id=?", (_id,)).fetchone()[0]
            sender = self.curs.execute("SELECT sender FROM Messages WHERE id=?", (_id,)).fetchone()[0]
            recepient = self.curs.execute("SELECT recepient FROM Messages WHERE id=?", (_id,)).fetchone()[0]
            key_old = crypto.aes_decrypt(key, old_key)
            data = crypto.aes_decrypt(data, key_old)
            key = crypto.generate_one_time_key(data)
            data = crypto.aes_encrypt(data.encode(), key)
            key = crypto.aes_encrypt(key, new_key)
            db.recrypt_message(_id, data, key) # Recrypt

# If script was started
if __name__ == "__main__":
    cmd = input("Enter command to execute: ")
    db = DB()
    if cmd == "clear": # If we wanna clear all db
        if bool(input("Are you sure you want to clear all db: user data, messages, friends? (1/0) ")):
            if bool(input("Are you really sure you want to clear all db: user data, messages, friends? (1/0) ")):
                db.clear_all()
    elif cmd == "recrypt": # If we wanna recrypt all db
        if bool(input("Are you sure you want to recrypt all user messages? (1/0) ")):
            new_key = getpass("Enter new key: ")
            new_key = new_key.encode()
            db.recrypt(DB_MSG_ENC_KEY, new_key)
    db.disconnect()
