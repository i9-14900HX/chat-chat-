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
from audio_player import *
from PyQt6.QtCore import QThread, pyqtSignal

# from audio_recorder import Recorder
class My_Error(Exception):
    #לעבוד על custom exceptions, לראות raise | except | try | finally | as e . נראה מגניב ביותר  
    pass
class Client(QThread):

    new_message_signal = pyqtSignal(str, str, str, int)  # msg_id, username, message, group_id
    new_audio_signal = pyqtSignal(str, str, int, str)  # msg_id, username, fileplace, group_id
    new_in_group = pyqtSignal(str, int)
    new_add_group = pyqtSignal(int, str)
    new_remv_group = pyqtSignal(int, str)
    new_serversays_signal = pyqtSignal(str)


    def __init__(self):
        super().__init__()
        self.client_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False

    def initialize_parameters(self):
        self.socket_lock = threading.Lock()
        self.not_duplicate_group = threading.Lock()
        self.audio_data_dic = {}
        self.message_queue = Queue()
        self.is_ack = threading.Event()
        self.is_ack.clear()
        self.is_ack_dic = {}
        self.default_group = 0
        self.in_group = 0

    def Connect_To_Server(self):
        #self.client_socket.connect(('127.0.0.1',6666))
        self.client_socket.connect(('10.100.102.8',6666))
        self.connected = True
        dh, pk = Cipher.get_dh_public_key()
        self.client_socket.send(pk)
        reply = self.client_socket.recv(2048)
        shared_key = Cipher.get_dh_shared_key(dh, reply)
        self.cipher = Cipher(shared_key, NONCE)
    
    def Get_in_Server(self, method, username, password):
            data_str = ""

            data = username + "@@@" + password
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
            return data_str


    def Start_Client(self):
        self.initialize_parameters()
        self.Server_Logistics() 
        
    
    
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
            msg_AES = self.message_queue.get()
            if msg_AES is None:
                break
                  # מחכה להודעה חדשה
            with self.socket_lock:
                if self.connected:
                    try:
                        self.client_socket.send(msg_AES)
                    except OSError:
                        break

            self.message_queue.task_done()
            self.is_ack.wait(timeout=5)
            self.is_ack.clear()


    def Server_Logistics(self):
        #    ping_thread = threading.Thread(target = self.Ping_Server)
        # vb    ping_thread.start()


            #recv_data_from_client_thread = threading.Thread(target = self.recv_data_from_client)
            #recv_data_from_client_thread.start()
            recv_data_from_server_and_Handle_thread = threading.Thread(target = self.recv_data_from_server_and_Handle)
            recv_data_from_server_and_Handle_thread.start()
            queue_thread = threading.Thread(target= self.Send_By_Queue)
            queue_thread.start()
    
    def recv_data_from_client(self): 
        self.DB_object_client_recvr = DB_file.DB_Class_Specific(self.username)
        self.player_object = Audio_player()
        while self.connected:
            input_in_string = input("send a message\n")

            if input_in_string.split("|")[0] == "stop":
                self.player_object.stop()
            elif input_in_string.split("|")[0] == "play":
                self.player_object.Play_Audio_By_File_thread = threading.Thread(target = self.player_object.Play_Audio_By_File, args=(input_in_string.split("|")[1],))
                self.player_object.Play_Audio_By_File_thread.start()
            elif input_in_string == "":
                continue
            elif input_in_string.split("|")[0] == "ADD":
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
                    self.in_group = self.default_group #לא יודע מה זה למה זה == ולא = 
                    continue
                else:
                    print(f"you are now in group: {input_in_string.split(":")[1]}")
                    self.in_group = want_group
                group_messages = self.DB_object_client_recvr.Get_Message_by_group(self.in_group)
                if not group_messages:
                    print("no messages in this group yet")
                    continue
                for msg in group_messages:
                    msg_type, msg_id, username_str, group_id, data = msg
                    if msg_type == "str":
                        print(f"{self.format_msg_id(msg_id)} {username_str} sent: {data}, group: {group_id} ,supposed to be from client\n")
                    elif msg_type == "wav":
                        print(f"{self.format_msg_id(msg_id)} {username_str} sent a voice message, group: {group_id} ,supposed to be from client\n")
                continue
            elif input_in_string == "<activate_voice_stream>":
                voice_recording_bytes = self.Get_Voice_Recording()
                self.send_server_recording(voice_recording_bytes, self.in_group)
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
            elif input_in_string.split("|")[0] == "RMV":
                if self.in_group == self.default_group:
                    print("cannot remove from broadcast")
                    continue
                else:
                    status, msg_AES = self.Remove_From_Group_Send_Server_Msg(input_in_string, self.in_group)
                    if status != None:
                        print(msg_AES)
                        continue 
                    else:
                        print("remove message sent to server")
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
        self.client_socket.send(self.cipher.aes_encrypt(b"elevenchars"))
        self.DB_object_server_recvr = DB_file.DB_Class_Specific(self.username)
        #self.client_socket.settimeout(10)
        while self.connected:
            try:
                header_encrypted = self.recv_exact(HEADER_SIZE)
            except (OSError) as e:
                self.connected = False
                print(f"error: {e}")
                break
            header = self.cipher.aes_decrypt(header_encrypted)
            msg_type_str, msg_id, chunk_idx, total_chunks, payload_len, username_str, group_id = UnPack_Header(header)
            if msg_type_str == "str":
                data_AES = self.recv_exact(payload_len)
                data_bytes = self.cipher.aes_decrypt(data_AES)
                data_str = data_bytes.decode()
                self.DB_object_server_recvr.Save_Message(msg_type_str, msg_id, username_str, group_id, data_str)
                self.new_message_signal.emit(username_str, data_str, msg_id, group_id)
                print(f"{self.format_msg_id(msg_id)} {username_str} sent: {data_str}, group: {group_id} ,supposed to be from client\n")
            elif msg_type_str == "wav":
                fine = True
                chunk_data_AES = self.recv_exact(payload_len)
                chunk_data_bytes = self.cipher.aes_decrypt(chunk_data_AES)

                if msg_id not in self.audio_data_dic:
                    if chunk_idx != 1:
                        print(f"Error: Received chunk {chunk_idx} for message ID {msg_id} before receiving the first chunk.")
                        fine = False
                        #continue אנחנו עדיין רוצים לשלוח ack
                    else:
                        self.audio_data_dic[msg_id] = {"vc_data": [], "total_chunks": total_chunks, "chunks_received": 0}

                if fine:
                    self.audio_data_dic[msg_id]["vc_data"].append(chunk_data_bytes)
                    self.audio_data_dic[msg_id]["chunks_received"] += 1
                    
                    if self.audio_data_dic[msg_id]["chunks_received"] == self.audio_data_dic[msg_id]["total_chunks"]:

                        data_bytes = self.audio_data_dic[msg_id]["vc_data"]
                        #self.DB_object_server_recvr.Save_audio_bytes_in_dir(data_bytes, msg_id)
                        self.DB_object_server_recvr.Save_Message(msg_type_str, msg_id, username_str, group_id, data_bytes)
                        self.new_audio_signal.emit(username_str, msg_id, group_id, str(self.DB_object_server_recvr.audio_dir / f"recording{msg_id}.wav"))

            elif msg_type_str == "ans":
                data_AES = self.recv_exact(payload_len)
                data_bytes = self.cipher.aes_decrypt(data_AES)
                data_str = data_bytes.decode()
                show, do = data_str.split("|", 1) #split only once 
                print(f"server says: {show}")
                self.Handle_Server_Ans(do)
                self.new_serversays_signal.emit(show)

            elif msg_type_str == "ack":
                self.is_ack.set()
                if msg_id in self.is_ack_dic:
                    self.is_ack_dic[msg_id].set()
                continue

            ack_msg = Generate_ACK_msg(msg_id, self.username, chunk_idx, total_chunks, group_id)
            ack_msg_AES = self.cipher.aes_encrypt(ack_msg)
            with self.socket_lock:
                    self.client_socket.send(ack_msg_AES)
            #except(ConnectionResetError, BrokenPipeError, OSError, socket.timeout) as e:
            #    if isinstance(e, socket.timeout):
            #        pass
            #    else:
            #        pass

            '''
            if meta_data_in_bytes_From_Server_type = b'<ACK>':
                self.is_ack.set()
                pass
            else:
            '''
    def Start_recording(self):
        self.recorder_class_object = Recorder()
        self.recorder_class_object.Start_Recording_thread = threading.Thread(target = self.recorder_class_object.Start_Recording)
        self.recorder_class_object.Start_Recording_thread.start()
    
    def Stop_recording(self):
        full_audio_recording_bytes = self.recorder_class_object.End_Recording()
        return full_audio_recording_bytes

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

            header = Pack_Header(msg_type_str, msg_id, chunk_idx, total_chunks, msg_len, self.username, group_id)

            header_AES = self.cipher.aes_encrypt(header)

            msg = header_AES + string_message_AES

            #return msg

            self.Send_Server_simple(msg)
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
    def send_server_recording(self, voice_recording_bytes, group_id):
        counter = 0 
        chunk_offset = 0
        bytes_sent = 0
        voice_recording_bytes_len = len(voice_recording_bytes)
        total_chunks = math.ceil(voice_recording_bytes_len/CHUNK_DATA_MAX_SIZE)
        msg_id = Generate_msg_id()
        self.is_ack_dic[msg_id] = threading.Event()
        while counter < total_chunks:
            chunk_bytes = voice_recording_bytes[chunk_offset:chunk_offset + CHUNK_DATA_MAX_SIZE]
            chunk_bytes_len = len(chunk_bytes)
            voice_message_chunk_AES = self.Client_Voice_Message(chunk_bytes, msg_id, counter + 1, total_chunks, chunk_bytes_len, group_id)
            #self.client_socket.send(voice_message_chunk_AES)
            if self.connected:
                self.message_queue.put(voice_message_chunk_AES)
            else:
                break
            chunk_offset += CHUNK_DATA_MAX_SIZE
            bytes_sent += chunk_bytes_len
            print(f"{bytes_sent/voice_recording_bytes_len*100}% sent")
            if not self.is_ack_dic[msg_id].wait(timeout=10):  # מחכה לאישור עם טיימאוט של 10 שניות
                print(f"Error: Server timed out on ACK for chunk {counter + 1}")
                # אופציונלי: אפשר לעשות פה 'break' כדי להפסיק הכל, 
                # או לנסות לשלוח שוב (Retry)
                break
            self.is_ack_dic[msg_id].clear()
            counter += 1
        return

    def Create_Group_Send_Server_Msg(self, group_name, users_list):
            
            #_ , group_name , users = message_raw.split("|")
            #_ , group_name , users = [u for u in message_raw.split("|") if u]
            #users += ' ' + self.username

            #user_list = users.split(' ')

            #group_name = group_name.strip()
            message = group_name + ','

            #if len(user_list) != len(set(user_list)):
            #    return "duplicate usernames"

            #for user in user_list:
            #    if not user:
            #        return "bad spacing/formatting"

            #if self.DB_object_client_recvr.Is_Group_Exist(group_name):
            #    return "Group name already exists, please change"

            for username in users_list:
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

            #return msg
            self.Send_Server_simple(msg)
    
    def Add_To_Group_Send_Server_Msg(self, message_raw: str, target_group):
            
            DB_object = DB_file.DB_Class_Specific(self.username)
            #_ , username = message_raw.split('|', 1)
            #target_group_id = self.DB_object_client_recvr.Get_Group_Id_From_Name(target_group)
            target_group_id = target_group
            username = message_raw
            target_user = username.strip()

            #if target_user in self.DB_object_client_recvr.Get_Group_Members(target_group_id, method = "list"):
                
            #    return "no", f"{username} already in {target_group}"
            
            msg = str(target_group_id) + "|" + target_user + "|" + DB_object.Get_Group_Name_From_Id(target_group_id)
            del DB_object

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

            #return None, header_msg_AES
            self.Send_Server_simple(header_msg_AES)
                
    def Remove_From_Group_Send_Server_Msg(self, message_raw: str, target_group):
            DB_object = DB_file.DB_Class_Specific(self.username)

            #_ , username = message_raw.split('|', 1)
            username = message_raw
            #target_group_id = self.DB_object_client_recvr.Get_Group_Id_From_Name(target_group)
            target_group_id = target_group
            target_user = username.strip()

            #if target_user not in self.DB_object_client_recvr.Get_Group_Members(target_group_id, method = "list"):
                
            #    return "no", f"{username} is not in {target_group}"
            
            msg = str(target_group_id) + "|" + target_user + "|" + DB_object.Get_Group_Name_From_Id(target_group_id)
            del DB_object

            msg_bytes = msg.encode()
            msg_AES = self.cipher.aes_encrypt(msg_bytes)

            msg_type_str = "rmv"
            msg_id = Generate_msg_id()
            chunk_idx = 0
            total_chunks = 0

            msg_len = len(msg_AES)
            
            header = Pack_Header(msg_type_str, msg_id, chunk_idx, total_chunks, msg_len, self.username, self.default_group)

            header_AES = self.cipher.aes_encrypt(header)

            header_msg_AES = header_AES + msg_AES

            #return None, header_msg_AES
            self.Send_Server_simple(header_msg_AES)

    def Create_Group_Internal_Client(self, command):

        print(f"create group command: {command}")
        _ , group_id , usernames , group_name = command.split(".", 3)

        '''
        origin_group_name = group_name
        group_unique_name_progressive_index = 1
        group_exist = True
        with self.not_duplicate_group:
            if self.DB_object_server_recvr.Is_Group_Exist(group_name):
                while group_exist:
                    group_name_new = group_name + f" ({group_unique_name_progressive_index})"  
                    if not self.DB_object_server_recvr.Is_Group_Exist(group_name_new):
                        group_name = group_name_new
                        group_exist = False
                    else:
                        group_unique_name_progressive_index += 1
                print(f"{origin_group_name} name taken, new name: {group_name}")
        '''

        print(f"creating group in client, {group_id} {usernames} {group_name}")
        self.DB_object_server_recvr.Create_Group(group_id, usernames, group_name)
        group_id = int(group_id)
        self.new_in_group.emit(group_name, group_id)

    def Add_To_Group_Internal_Client(self, do):

        _ , target_group_id, target_username = do.split(".")

        self.DB_object_server_recvr.Add_To_Group(target_group_id, target_username)

        print("client_added_succesfully in client")

        target_group_id = int(target_group_id)

        self.new_add_group.emit(target_group_id, target_username)

    def Remove_From_Group_Internal_Client(self, do):
        
        do_instructions = do.split(".")

        if len(do_instructions) == 2:
            _ , target_group_id = do_instructions
            target_username = self.username
        else:
            _ , target_group_id, target_username = do_instructions

        self.DB_object_server_recvr.Remove_From_Group(target_group_id, target_username)

        target_group_id = int(target_group_id)


        self.new_remv_group.emit(target_group_id, target_username)

        print("client_removed_succesfully in client")
    
    def Handle_Server_Ans(self, do):

        if not do:
            print("no do")
            return
        
        
        method = do.split(".")[0]

        match method:
            case "crt":
                self.Create_Group_Internal_Client(do)       
            case "add":
                self.Add_To_Group_Internal_Client(do)
            case "rmv":
                self.Remove_From_Group_Internal_Client(do)
            case _:
                print(f"method {method} is not in the system")

    def close_client(self):
        '''
        print("starting client shutdown")
        self.connected = False
        time.sleep(0.1)
        self.client_socket.close()
        '''
        print("Initiating client shutdown...")
        self.connected = False
        
        # "הזרקת" הודעת סיום לתור כדי לשחרר את ה-get() המחכה
        if hasattr(self, 'message_queue'):
            self.message_queue.put(None) 
        
        # שחרור ה-Event של ה-ACK אם מישהו מחכה לו
        if hasattr(self, 'is_ack'):
            self.is_ack.set()

        try:
            # סגירת הסוקט בצורה אגרסיבית יותר כדי להפסיק recv_exact תקוע
            self.client_socket.shutdown(socket.SHUT_RDWR)
            self.client_socket.close()
        except OSError:
            pass # הסוקט כבר סגור
        
        print("Client socket closed.")
            


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