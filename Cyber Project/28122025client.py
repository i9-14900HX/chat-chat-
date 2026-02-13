import socket
import threading
import time
from pathlib import Path
from cipher import *
from constants import *
from audio_recorder import *
from Header_packer_and_unpacker import *
import math
from queue import Queue
import DB_file
from tqdm import tqdm
 
# from audio_recorder import Recorder
class My_Error(Exception):
    #לעבוד על custom exceptions, לראות raise | except | try | finally | as e . נראה מגניב ביותר  
    pass
class Client:
    def __init__(self):
        self.socket_lock = threading.Lock()
        self.audio_data_dic = {}
        data_str = ''
        self.message_queue = Queue()
        self.is_ack = threading.Event()
        self.is_ack.clear()
        self.default_group = 0
        self.in_group = 0
        self.client_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(('127.0.0.1',6666))
        self.connected = True
        dh, pk = Cipher.get_dh_public_key()
        self.client_socket.send(pk)
        reply = self.client_socket.recv(2048)
        shared_key = Cipher.get_dh_shared_key(dh, reply)
        print("shared key:", shared_key)
        self.cipher = Cipher(shared_key, NONCE)
        while not data_str == 'You are In':

            print("Enter username, make sure the username is between 3-16 characters, and includes only letters and numbers")
            self.username = self.Get_Good_Username()

            print("Enter password, make sure the username is between 3-16 characters, and includes only letters and numbers")
            self.password = self.Get_Good_Password()

            method = input("would you like to sign up or sign in? write sin or sup accordingly\n")

            data = self.username + "@@@" + self.password
            data_len = len(data)

            header = Pack_Header(method , "0", 0, 0, data_len, "0", 0)

            message = self.cipher.aes_encrypt(header) + self.cipher.aes_encrypt(data.encode())

            self.client_socket.send(message)

            header_encrypted= self.recv_exact(HEADER_SIZE)
            header = self.cipher.aes_decrypt(header_encrypted)
            _ , _ , _ , _ , payload_len, _ , _ = UnPack_Header(header)
            data_AES = self.recv_exact(payload_len)
            data_bytes = self.cipher.aes_decrypt(data_AES)                
            data_str = data_bytes.decode()
            print(data_str)

        
        self.Server_Logistics() 

    def Get_Good_Username(self):
        is_bad = True
        while is_bad:
           username = input()
           if 3 > len(username) or len(username) > 16:
                print("bad username - too short or long")  
                continue
           if not username.isalnum():
                print("bad username - unsupported characters")  
                continue
           is_bad = False
        print("acceptable. have a nice day.")
        return username
    
    def Get_Good_Password(self):
        is_bad = True
        while is_bad:
           password = input()
           if 3 > len(password) or len(password) > 16:
                print("bad password - too short or long")  
                continue
           if not password.isalnum():
                print("bad password - unsupported characters")  
                continue
           is_bad = False
        print("acceptable. have a nice day.")
        return password
    
    def format_msg_id(self, msg_id_str: str) -> str:

        """
        Convert an 18-digit message ID string like '260111152045123456'
        into human-readable format: 'YYYY/MM/DD - HH:MM'
        """
        if len(msg_id_str) != 18 or not msg_id_str.isdigit():
            raise ValueError("msg_id_str must be an 18-digit string")

        year = int(msg_id_str[0:2]) + 2000  # assumes 2000+
        month = msg_id_str[2:4]
        day = msg_id_str[4:6]
        hour = msg_id_str[6:8]
        minute = msg_id_str[8:10]
        # seconds = msg_id_str[10:12]  # unused
        # microseconds = msg_id_str[12:]  # unused

        return f"{year}/{month}/{day} - {hour}:{minute}"
    
    def Send_By_Queue(self):
        while self.connected:
            msg_AES = self.message_queue.get()  # מחכה להודעה חדשה
            with self.socket_lock:
                self.client_socket.send(msg_AES)
            self.message_queue.task_done()
            self.is_ack.wait()
            self.is_ack.clear()


    def Server_Logistics(self):
        #    ping_thread = threading.Thread(target = self.Ping_Server)
        # vb    ping_thread.start()


            recv_data_from_client_thread = threading.Thread(target = self.recv_data_from_client)
            recv_data_from_client_thread.start()
            recv_data_from_server_and_Handle_thread = threading.Thread(target = self.recv_data_from_server_and_Handle)
            recv_data_from_server_and_Handle_thread.start()
            queue_thread = threading.Thread(target= self.Send_By_Queue)
            queue_thread.start()

    def recv_data_from_client(self): 
        self.DB_object_client_recvr = DB_file.DB_Class_Specific(self.username)
        while self.connected:
            input_in_string = input("send a message\n")
            if input_in_string.split("|")[0] == "ADD":
                if self.in_group == self.default_group:
                    print("cannot add to broadcast")
                    continue
                else:
                    status, msg_AES = self.Add_To_Group_Send_Server_Msg(input_in_string, self.in_group)
                    if status != None:
                        print(msg_AES)
                        continue 
                    else:
                        print("add message sent to server")
                        self.Send_Server_simple(msg_AES)
            elif input_in_string.split(":")[0] == "change group":
                want_group = self.DB_object_client_recvr.Get_Group_Id_From_Name(input_in_string.split(":")[1]) 
                if want_group == None:
                    print(f"no group: {input_in_string.split(":")[1]}, you are now in broadcast")
                    self.in_group == self.default_group
                    continue
                else:
                    print(f"you are now in group: {input_in_string.split(":")[1]}")
                    self.in_group = want_group
                continue
            elif input_in_string == "<activate_voice_stream>":
                voice_recording_bytes = self.Get_Voice_Recording()
                self.Send_Server_recording(voice_recording_bytes, self.in_group)
            elif input_in_string.split("|")[0] == "CRT":
                msg_AES = self.Create_Group_Send_Server_Msg(input_in_string)
                if msg_AES == "duplicate usernames":
                    print(msg_AES)
                    continue

                if msg_AES == "bad spacing/formatting":
                    print(msg_AES)
                    continue
                
                if msg_AES == "Group name already exists, please change":
                    print(msg_AES)
                    continue

                self.Send_Server_simple(msg_AES)
            else:
                msg_AES = self.Client_string_message(input_in_string, self.in_group)
                self.Send_Server_simple(msg_AES)
        '''
    def Handle_data_str_message(self, meta_data_type, data_AES):
        full_meta_data, meta_data_length_int = self.Generate_meta_data_by_method(data_AES, meta_data_type, "AES")
        self.Send_Server(data_AES, full_meta_data, meta_data_length_int)
        
        if is_small:
            self.Send_Small(data_AES, full_meta_data)
        else:
            self.Send_Big(data_AES, full_meta_data)
        '''
    def recv_exact(self, nbytes: int) -> bytes:
        data = bytearray()

        while len(data) < nbytes:
            chunk = self.client_socket.recv(nbytes - len(data))
            if not chunk:
                raise ConnectionError("Socket closed while receiving data")
            data.extend(chunk)
        return bytes(data)
    
    def recv_data_from_server_and_Handle(self):
        self.DB_object_server_recvr = DB_file.DB_Class_Specific(self.username)
        while self.connected:
            header_encrypted = self.recv_exact(HEADER_SIZE)
            header = self.cipher.aes_decrypt(header_encrypted)
            msg_type_str, msg_id, chunk_idx, total_chunks, payload_len, username_str, group_id = UnPack_Header(header)
            if msg_type_str == "str":
                data_AES = self.recv_exact(payload_len)
                data_bytes = self.cipher.aes_decrypt(data_AES)
                data_str = data_bytes.decode()
                print(f"{self.format_msg_id(msg_id)} {username_str} sent: {data_str}, group: {group_id} ,supposed to be from client\n")
            elif msg_type_str == "wav":
                chunk_data_AES = self.recv_exact(payload_len)
                chunk_data_bytes = self.cipher.aes_decrypt(chunk_data_AES)

                if msg_id not in self.audio_data_dic:
                    self.audio_data_dic[msg_id] = {"vc_data": [], "total_chunks": total_chunks, "chunks_received": 0}
 
                self.audio_data_dic[msg_id]["vc_data"].append(chunk_data_bytes)
                self.audio_data_dic[msg_id]["chunks_received"] += 1
                
                if self.audio_data_dic[msg_id]["chunks_received"] == self.audio_data_dic[msg_id]["total_chunks"]:

                    data_bytes = self.audio_data_dic[msg_id]["vc_data"]
                    self.DB_object_server_recvr.Save_audio_bytes_in_dir(data_bytes, msg_id)
                    
            elif msg_type_str == "ans":
                data_AES = self.recv_exact(payload_len)
                data_bytes = self.cipher.aes_decrypt(data_AES)
                data_str = data_bytes.decode()
                show, do = data_str.split("|", 1) #split only once 
                print(f"server says: {show}")
                self.Handle_Server_Ans(do)

            elif msg_type_str == "ack":
                self.is_ack.set()
                continue

            ack_msg = Generate_ACK_msg(msg_id, username_str)
            ack_msg_AES = self.cipher.aes_encrypt(ack_msg)
            with self.socket_lock:
                    self.client_socket.send(ack_msg_AES)

            '''
            if meta_data_in_bytes_From_Server_type = b'<ACK>':
                self.is_ack.set()
                pass
            else:
            '''
            

    def Get_Voice_Recording(self):
            
            recorder_class_object = Recorder()
            recorder_class_object.Start_Recording_thread = threading.Thread(target = recorder_class_object.Start_Recording)
            recorder_class_object.Start_Recording_thread.start()
            keyboard.wait('s')
            full_audio_recording_bytes = recorder_class_object.End_Recording()
            recorder_class_object.Start_Recording_thread.join()
            #full_audio_recording_AES = self.cipher.aes_encrypt(full_audio_recording_bytes)
            return full_audio_recording_bytes
    
    def Client_string_message(self, string_message, group_id):
            
            msg_type_str = "str"
            msg_id = Generate_msg_id()
            chunk_idx = 0
            total_chunks = 0
            
            string_message_bytes = string_message.encode()
            string_message_AES = self.cipher.aes_encrypt(string_message_bytes)

            msg_len = len(string_message_AES)
            
            group_id = self.in_group

            header = Pack_Header(msg_type_str, msg_id, chunk_idx, total_chunks, msg_len, self.username, group_id)

            header_AES = self.cipher.aes_encrypt(header)

            msg = header_AES + string_message_AES

            return msg
            #print(data_AES_To_Server)
            #self.client_socket.send(data_AES_To_Server)
    def Send_Server_simple(self, msg_AES):
        self.message_queue.put(msg_AES)
        #self.client_socket.send(msg_AES)
         
    def Client_Voice_Message(self, chunk_bytes, msg_id, chunk_idx, total_chunks, chunk_bytes_len, group_id):
        msg_type = "wav"
        header = Pack_Header(msg_type, msg_id, chunk_idx, total_chunks, chunk_bytes_len, self.username, group_id)
        header_AES = self.cipher.aes_encrypt(header)
        voice_message_chunk_AES = self.cipher.aes_encrypt(chunk_bytes)
        header_plus_voice_message_chunk_AES = header_AES + voice_message_chunk_AES
        return header_plus_voice_message_chunk_AES    
    
    ''''''
    def Send_Server_recording(self, voice_recording_bytes, group_id):
        counter = 0 
        chunk_offset = 0
        bytes_sent = 0
        voice_recording_bytes_len = len(voice_recording_bytes)
        total_chunks = math.ceil(voice_recording_bytes_len/CHUNK_DATA_MAX_SIZE)
        msg_id = Generate_msg_id()
        while counter < total_chunks:
            chunk_bytes = voice_recording_bytes[chunk_offset:chunk_offset + CHUNK_DATA_MAX_SIZE]
            chunk_bytes_len = len(chunk_bytes)
            voice_message_chunk_AES = self.Client_Voice_Message(chunk_bytes, msg_id, counter + 1, total_chunks, chunk_bytes_len, group_id)
            #self.client_socket.send(voice_message_chunk_AES)
            self.message_queue.put(voice_message_chunk_AES)
            chunk_offset += CHUNK_DATA_MAX_SIZE
            bytes_sent += chunk_bytes_len
            print(f"{bytes_sent/voice_recording_bytes_len*100}% sent")
            self.is_ack.wait()
            self.is_ack.clear()
            counter += 1
        return

    def Create_Group_Send_Server_Msg(self, message_raw):
            
            #_ , group_name , users = message_raw.split("|")
            _ , group_name , users = [u for u in message_raw.split("|") if u]
            users += ' ' + self.username

            user_list = users.split(' ')

            message = group_name + ','

            if len(user_list) != len(set(user_list)):
                return "duplicate usernames"

            for user in user_list:
                if not user:
                    return "bad spacing/formatting"

            if self.DB_object_client_recvr.Is_Group_Exist(group_name):
                return "Group name already exists, please change"

            for username in user_list:
                message += username + '|'
                 
            msg_type_str = "crt"
            msg_id = Generate_msg_id()
            chunk_idx = 0
            total_chunks = 0
            
            string_message_bytes = message.encode()
            string_message_AES = self.cipher.aes_encrypt(string_message_bytes)

            msg_len = len(string_message_AES)
            
            header = Pack_Header(msg_type_str, msg_id, chunk_idx, total_chunks, msg_len, self.username, self.default_group)

            header_AES = self.cipher.aes_encrypt(header)

            msg = header_AES + string_message_AES

            return msg
    
    def Add_To_Group_Send_Server_Msg(self, message_raw: str, target_group):
            
            _ , username = message_raw.split('|')
            #target_group_id = self.DB_object_client_recvr.Get_Group_Id_From_Name(target_group)
            target_group_id = target_group
            target_user = username.strip()

            if target_user in self.DB_object_client_recvr.Get_Group_Members(target_group_id, method = "list"):
                
                return "no", f"{username} already in {target_group}"
            
            msg = str(target_group_id) + "|" + target_user
            msg_bytes = msg.encode()
            msg_AES = self.cipher.aes_encrypt(msg_bytes)

            msg_type_str = "add"
            msg_id = Generate_msg_id()
            chunk_idx = 0
            total_chunks = 0

            msg_len = len(msg_AES)
            
            header = Pack_Header(msg_type_str, msg_id, chunk_idx, total_chunks, msg_len, self.username, self.default_group)

            header_AES = self.cipher.aes_encrypt(header)

            header_msg_AES = header_AES + msg_AES

            return None, header_msg_AES
    
    def Create_Group_Internal_Client(self, command):

        print(f"create group command: {command}")
        _ , group_id , usernames , group_name = command.split(".")
        self.DB_object_server_recvr.Create_Group(group_id, usernames, group_name)
    
    def Handle_Server_Ans(self, do):

        if not do:
            return
        
        method = do.split(".")[0]

        match method:
            case "crt":
                self.Create_Group_Internal_Client(do)       

            case _:
                print(f"method {method} is not in the system")



        


    '''
    def Send_Server(self, data_AES, meta_data_AES, data_len_int):
        self.ack = False
        bytes_sent = 0
        chunk_max_size = 1024
        chunk_offset = 0
        self.client_socket.send(meta_data_AES)
        while bytes_sent < data_len_int:
            self.is_ack.clear()
            self.ack = False
            chunk = data_AES[chunk_offset:chunk_offset + chunk_max_size]
            self.client_socket.send(chunk)
            chunk_offset += 1024
            bytes_sent += 1024
            if bytes_sent > data_len_int:
                bytes_sent = data_len_int
            print(f"{bytes_sent/data_len_int*100}% sent")
            self.is_ack.wait()
           # here = self.client_socket.recv(4)
           # print(self.cipher.aes_decrypt(here).decode() + "got here")


    
            
    def Generate_meta_data_by_method(self, data_AES, data_type_str, method):
            meta_data_length_int = len(data_AES)
            meta_data_length_str = str(meta_data_length_int)
            meta_data_str = data_type_str + meta_data_length_str 
            if method == "str":
                return meta_data_str, meta_data_length_int
            meta_data_length_byte = meta_data_length_int.to_bytes(4, 'big')
            data_type_bytes = data_type_str.encode()
            meta_data_bytes = data_type_bytes + meta_data_length_byte
            if method == "bytes":
                return meta_data_bytes, meta_data_length_int
            meta_data_aes = self.cipher.aes_encrypt(meta_data_bytes)
            if method == "AES":
                return meta_data_aes, meta_data_length_int
            print("oh no... get back to work")

    
   def Ping_Server(self):
        while self.connected:
            ping = "<Client_Pinging_Server_Do_Not_Kick>"
            ping_bytes = ping.encode()
            ping_AES = self.cipher.aes_encrypt(ping_bytes)
            self.client_socket.send(ping_AES)
            time.sleep(5) 
    '''
#if __name__ == "__main__": 


Client()