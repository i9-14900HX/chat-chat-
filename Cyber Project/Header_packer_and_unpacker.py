import os
import struct 
from constants import *
from datetime import datetime

@staticmethod
def Pack_Header(msg_type_str, msg_id, chunk_idx, total_chunks, payload_len, username_str, group_id):
    match msg_type_str:
        case "str":
            msg_type = STR
        case "wav":
            msg_type = WAV
        case "ack":
            msg_type = ACK
        case "req":
            msg_type = REQ
        case "ans":
            msg_type = ANS
        case "sin":
            msg_type = SIN
        case "sup":
            msg_type = SUP
        case "crt":
            msg_type = CRT
        case "add":
            msg_type = ADD
        case _:
            print("ERROR LINE 14 HEADER_MANAGER MODULE")
    print(f"packing: {msg_type_str}")

    msg_id = msg_id.encode("UTF-8")

    username = username_str.encode("UTF-8")
    username = username.ljust(USERNAME_SIZE, b'\x00')

    header = struct.pack(
    HEADER_FORMAT,
    msg_type,
    msg_id,
    chunk_idx,
    total_chunks,
    payload_len,
    username, 
    group_id
)

    return header

@staticmethod
def UnPack_Header(header):

    msg_type, msg_id, chunk_idx, total_chunks, payload_len, username_bytes, group_id = struct.unpack(HEADER_FORMAT, header)


    match msg_type:
        case 1:
            msg_type_str = "str"
        case 2:
            msg_type_str = "wav"
        case 3:
            msg_type_str = "ack"
        case 4:
            msg_type_str = "req"
        case 5:
            msg_type_str = "ans"
        case 6:
            msg_type_str = "sin"
        case 7:
            msg_type_str = "sup"
        case 8:
            msg_type_str = "crt"
        case 9:
            msg_type_str = "add"
        case _:
            print(f"ERROR LINE 45 HEADER_MANAGER MODULE: {msg_type}")

    print(f"unpacking: {msg_type_str}")

    msg_id = msg_id.decode("UTF-8")

    username_str = username_bytes.rstrip(b'\x00').decode("UTF-8")

    return msg_type_str, msg_id, chunk_idx, total_chunks, payload_len, username_str, group_id

@staticmethod
def Generate_msg_id():
   #msg_id = int.from_bytes(os.urandom(4), byteorder='big')
    msg_id = datetime.now().strftime("%y%m%d%H%M%S%f")
    return msg_id

@staticmethod
def Generate_ACK_msg(msg_id, username):
    return Pack_Header("ack", msg_id, 0, 0, 0, username, 0)