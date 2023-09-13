# ZiChat
ZiChat is an encrypted private anonymous chat app.

### About ZiChat.

ZiChat is an encrypted private anonymous chat app. It uses mode cryptographic algorithms to make client's data safe.

### ZiChat's features:
- Asymmetric + symmetric encryption makes all transfered data between server and client safe
- ZiChat don't collect any clien's metadata, except message timestamps
- Messages in DB are all encrypted with one-time key, that's encrypted with DB master key
- DB passwords are stored in hash
- DB can be reseted to save client's data from hackers
- and much another features

### Published code:

1) Client-side code
2) Server-side code
3) Simple website for chat app

### Server commands:

You can run ```python3 db.py``` to fully reset DB or recrypt it using new DB key.

You can change such settings (values.py) as message history (default 100), blacklisted usernames, passwords, symbols, etc.

### Client commands:

```:dis```                                    - disconnect from server

```:help```                                   - help with commands
 
```:friends```                                - view your friends

```:requests```                               - view all friends requests

```:add      [username]```                    - send friend request to username

```:remove   [username]```                    - delete friend

```:accept   [username]```                    - accept friend request from username

```:decline  [username]```                    - decline friend request from username

```:load     [username]```                    - load last 100 messages from chat with username

```:change   [old_password] [new_password]``` - change password


### Instructions:
1) Deploy server:

  To deploy server you need to upload it to the host (linux recommended). Make sure python3.10 at least is installed. Then you should edit config and enter host's ip, port and imagine it's name. Then install all needed libraries: run ```pip install -r   'requirenments.txt'```. Then run ```python3 server.py *** ```, where *** is DB encryption key (32 symbols). You can also run simple website using apache.

2) Build client:
    
  Don't forget to edit config.py!
   - For windows:
     To compile all scripts to .exe, you need to install nuitka and run ```nuitka client.py --standalone --onefile --follow-imports```.
   - For linux:
       You can either use python files that are in "Client folder" or obfuscate code using pyarmor: ```pyarmor gen *.py```.
