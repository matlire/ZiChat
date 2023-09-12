from typing import Final
from getpass import getpass
import sys
# MUSTN'T BE CHANGED!



# Client & Server values
MSG_MAX_SIZE          : Final[int]   = 4096 # Max message size
MAC_SIZE              : Final[int]   = 128  # MAC (message authentication code) size
SESSION_KEY_SIZE      : Final[int]   = 128  # Session key size
SESSION_KEY_ENC_SIZE  : Final[int]   = 144  # Session key encrypted size
SESSION_KEY_MAC_SIZE  : Final[int]   = 64   # Session key's MAC size
PRIVATE_KEY_SIZE      : Final[int]   = 32   # Private key size
MAC_KEY_SIZE          : Final[int]   = 128  # MAC key size
PKCS7_SIZE            : Final[int]   = 128  # PKCS7 size
PUBLIC_KEY_SIZE       : Final[int]   = 259  # Public key size
PRIVATE_KEY_KEY_SIZE  : Final[int]   = 64   # Key for private key generating size
HASH_SALT_SIZE        : Final[int]   = 32   # Salt size for hashing
STATUS_SIZE           : Final[int]   = 260  # Size for status
USERNAME_SIZE_TO      : Final[int]   = 16   # Username max size

SERVER_KILL_CMD       : Final[str]   = "kill" # Command to disconnect client on server killed
HELP_MSG              : Final[str]   = """ 
ZiChat is an encrypted private anonymous chat app.

Commands:
:dis                                  - disconnect from server
:help                                 - help with commands
:friends                              - view your friends
:requests                             - view all friends requests
:add [username]                       - send friend request to username
:remove [username]                    - delete friend
:accept [username]                    - accept friend request from username
:decline [username]                   - decline friend request from username
:load [username]                      - load last 100 messages from chat with username
:change [old_password] [new_password] - change password

Message history=100, special symbols in username are not allowed, some of them are also forbidden in password; There are some blacklisted usernames.

If sothing went wrong, just press Ctrl+C several times;)

Our official website: http://XXXXXX
"""

STATUS_CODES = {        # Status codes
    "FAILHOST":   "0",  # Failed hosting STRING=INT!
    "SUCCESS":    "1",  # Success
    "NOUSER":     "2",  # No such user
    "INCPASS":    "3",  # Incorrect password
    "NOPASSMAT":  "4",  # Passwords don't match
    "USERIN":     "5",  # User already online
    "INCUSERLEN": "6",  # Username incorrect size
    "INCPASSLEN": "7",  # Password incorrect size
    "CHECK":      "8",  # Check online
    "INCUSERF":   "9",  # Username incorrect format
    "INCPASSF":   "10", # Password incorrect format
    "FRREQSNT":   "11", # Friends request already sent
    "INVARGS":    "12", # Invalid arguments
    "NOTFRDS":    "13", # You are not friends
    "VERSCHECK":  "14", # Version mismatch
}

COMMANDS = {                  # Commands
    "DISCONNECT": "dis",      # Disconnect from server
    "HELP":       "help",     # Help
    "FRIENDS":    "friends",  # View all friends
    "REQUESTS":   "requests", # View all friends requests
    "ADD":        "add",      # Send friend request to 
    "REMOVE":     "remove",   # Delete friend
    "ACCEPT":     "accept",   # Accept friend request from 
    "DECLINE":    "decline",  # Decline friend request from
    "LOAD":       "load",     # Load last 100 messages from chat with
    "CHANGE":     "change",   # Change password
}

# Symbols and words blacklists
WORD_BLACKLIST                       = ["Friends", "-----", "Corrupted", "CORRUPTED", "corrupted"] + list(COMMANDS.keys()) + list(COMMANDS.values()) + list(STATUS_CODES.keys()) + list(STATUS_CODES.values())
SYMBOL_BLACKLIST      : Final[str]   = "+=- \"'\\|/<>()[],.;:"


# Server values
SESSION_MSG_SIZE      : Final[int]   = SESSION_KEY_ENC_SIZE + SESSION_KEY_MAC_SIZE # Session full message size
LOG_REG_DATA_SIZE     : Final[int]   = 292                                         # Username, password encrypted message size
USERNAME_SIZE_FROM    : Final[int]   = 4                                           # Username min size
PASSWORD_SIZE_FROM    : Final[int]   = 4                                           # Password min size
PASSWORD_SIZE_TO      : Final[int]   = 32                                          # Password max size
DB_MSG_ENC_KEY        : Final[bytes] = bytes(sys.argv[1].encode())                 # Key to encrypt messages in db
MAX_FRIENDS           : Final[int]   = 64                                          # Max user's friends   
HISTORY_SIZE          : Final[int]   = 100                                         # Size of loaded chat history per 1 scroll
SERVER_NAME           : Final[str]   = "XXXXXX-SERVER"                             # Server name
WORD_BLACKLIST.append(SERVER_NAME)
MAX_CLIENTS           : Final[int]   = 100                                         # Max clients
BACKUP_CMD            : Final[str]   = "backup"
DB_NAME               : Final[str]   = "ZiChatDB.sqlite"
VERSION               : Final[str]   = "0.0.0.0.1"                                 # Server version

"""
VERSIONS:
Alpha:
0.0.x.x.x

Beta-closed:
0.1.x.x.x

Beta-open:
0.2.x.x.x

Hotfixed:
0.3.x.x.x

Main:
1.x.x.x.x
"""
