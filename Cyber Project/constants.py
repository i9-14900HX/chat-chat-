import struct 

#cipher:
NONCE = b"Encryption is the process of transforming information into a form that is unreadable"

#header:
HEADER_FORMAT = "!B 18s I I H 16s H"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
USERNAME_SIZE = 16

STR = 1
WAV = 2 
ACK = 3
REQ = 4
ANS = 5
SIN = 6
SUP = 7 
CRT = 8
ADD = 9
RMV = 10

#protocol
CHUNK_MAX_SIZE = 1027
CHUNK_DATA_MAX_SIZE = CHUNK_MAX_SIZE - HEADER_SIZE