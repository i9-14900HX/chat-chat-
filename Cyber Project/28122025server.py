import math
import socket
from pathlib import Path
import threading
from cipher import *
from constants import *
from Header_packer_and_unpacker import *
import struct 
import os 
import soundfile as sf
import numpy as np
import DB_file 
from queue import Queue
import time

class Server:
    def __init__(self):
        self.file_path = Path(__file__).resolve()
        self.folder_path = self.file_path.parent
        self.audio_dir = self.folder_path / "audio_recordings_wav"
        self.audio_dir_str = str(self.audio_dir)
        self.audio_dir.mkdir(parents=True, exist_ok=True)
        self.username_password_salt_db = str(self.folder_path / "username_password_salt_db.db")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('127.0.0.1', 6666))
        server.listen(100) 
        print("server on...")
        self.clients_currently_on = 0
        self.broadcast_id = 0
        #self.clients_list = []
        self.users_set = set()
        self.client_dic = {}
        self.temp_recconect_dic = {}
        self.place_holder_key = "place_holder_key"
        temporary_db_object = DB_file.DB_Class_General()
        self.group_id_counter = temporary_db_object.Get_Current_Group_Id()
        self.sup_lock = threading.Lock()
        self.client_dic_lock = threading.Lock()
        self.temp_recconect_dic_lock = threading.Lock()
        self.group_id_counter_lock = threading.Lock()
        self.edit_group_lock = threading.Lock()
        self.users_set_lock = threading.Lock()
        while True:
            client_socket,address=server.accept()
            #client_socket.settimeout(10)
            self.clients_currently_on += 1
            print(f"client number {self.clients_currently_on} is connected")
            client_thread = threading.Thread(target = self.Single_Client_With_Thread, args=(client_socket, address))
            client_thread.start()

    def recv_exact(self, sock, nbytes: int) -> bytes:
        data = bytearray()

        while len(data) < nbytes:
            chunk = sock.recv(nbytes - len(data))
            if not chunk:
                raise ConnectionError("Socket closed while receiving data")
            data.extend(chunk)
        return bytes(data)

    def Handle_Client_Data(self, meta_data_type_bytes, meta_data_len_int, client_socket, cipher):
        zero = 0
        ack_message = b'<ACK>'+zero.to_bytes(4, 'big')
        bytes_left = meta_data_len_int
        rounds = 0
        aes_data = b''
        while bytes_left != 0:
            try:
                recv_index = min(1024, bytes_left)
                aes_data += client_socket.recv(recv_index)
                rounds += 1 
                bytes_left-= recv_index
                client_socket.send(cipher.aes_encrypt(ack_message))
            except (ConnectionResetError, BrokenPipeError): #except (socket.timeout, ConnectionResetError, BrokenPipeError):
                raise
        return cipher.aes_decrypt(aes_data)
    
    def Send_Client_By_Q(self, queue, socket, socket_lock, ack_evnt):
        try: 
            while True:
                msg_AES = queue.get()  # מחכה להודעה חדשה
                with socket_lock:
                    socket.send(msg_AES)
                queue.task_done()
                ack_evnt.wait()
                ack_evnt.clear()
        except (ConnectionResetError, BrokenPipeError, OSError):
            raise 
        
    def Single_Client_With_Thread(self, client_socket, address):
        
        #stop_q = threading.Event()
        is_in_set = False
        client_in = False
        msg_id_dic = {}
        client_connected = True
        DB_object = DB_file.DB_Class_General()
        socket_lock = threading.Lock()
        ack_evnt = threading.Event()
        #?client_ping_bytes = b"<Client_Pinging_Server_Do_Not_Kick>"
        try: 
            dh, pk = Cipher.get_dh_public_key()
            client_pk = client_socket.recv(1024)
            if not client_pk:
                raise OSError
            shared_key = Cipher.get_dh_shared_key(dh, client_pk)
            print("shared key:", shared_key)
            client_socket.send(pk)
            cipher = Cipher(shared_key, NONCE)
            while not client_in:
                header_encrypted= self.recv_exact(client_socket, HEADER_SIZE)
                if not header_encrypted:
                    raise OSError
                header = cipher.aes_decrypt(header_encrypted)
                method , msg_id, chunk_idx, total_chunks, payload_len, username_str, group_id = UnPack_Header(header)
                data_AES = self.recv_exact(client_socket, payload_len)
                data_bytes = cipher.aes_decrypt(data_AES)
                data_str = data_bytes.decode()
                name=data_str.split('@@@')[0]
                password=data_str.split('@@@')[1]

                if method == "sup":
                    with self.sup_lock:
                        if DB_object.username_exist(name):
                            print('user already exist - try another user name')
                            encrypted_answer=cipher.aes_encrypt('user already exist - try another user name'.encode())
                            header = Pack_Header("ans",msg_id, chunk_idx, total_chunks, len(encrypted_answer), username_str, group_id)
                            encrypted_header = cipher.aes_encrypt(header)
                            msg_AES = encrypted_header + encrypted_answer
                            client_socket.send(msg_AES)

                        else:
                            DB_object.save_user_and_pass(name,password)
                            print('new user sign up complete',name)
                            encrypted_answer=cipher.aes_encrypt('new user sign up complete'.encode())
                            header = Pack_Header("ans",msg_id, chunk_idx, total_chunks, len(encrypted_answer), username_str, group_id)
                            encrypted_header = cipher.aes_encrypt(header)
                            msg_AES = encrypted_header + encrypted_answer
                            client_socket.send(msg_AES)
                            
                elif method == "sin":
                    if not DB_object.username_exist(name):
                        print('username not exist',name)
                        encrypted_answer=cipher.aes_encrypt('username not exist'.encode())
                        header = Pack_Header("ans",msg_id, chunk_idx, total_chunks, len(encrypted_answer), username_str, group_id)
                        encrypted_header = cipher.aes_encrypt(header)
                        msg_AES = encrypted_header + encrypted_answer
                        client_socket.send(msg_AES)
                        
                    elif not DB_object.check_password(name,password):
                        print('wrong password',name)
                        encrypted_answer=cipher.aes_encrypt('wrong password'.encode())
                        header = Pack_Header("ans",msg_id, chunk_idx, total_chunks, len(encrypted_answer), username_str, group_id)
                        encrypted_header = cipher.aes_encrypt(header)
                        msg_AES = encrypted_header + encrypted_answer
                        client_socket.send(msg_AES)
                    else:
                        with self.users_set_lock:
                            if name in self.users_set:
                                print(f"{name} connected already")
                                encrypted_answer=cipher.aes_encrypt('user already connected'.encode())
                                header = Pack_Header("ans",msg_id, chunk_idx, total_chunks, len(encrypted_answer), username_str, group_id)
                                encrypted_header = cipher.aes_encrypt(header)
                                msg_AES = encrypted_header + encrypted_answer
                                client_socket.send(msg_AES)
                                continue #שכחתי פה continu ואז השרת העביר את השמתמש הלאה והיה קריסה
                            else:
                                self.users_set.add(name)
                                is_in_set = True    
                        client_in = True
                        encrypted_answer=cipher.aes_encrypt('You are In'.encode())
                        header = Pack_Header("ans",msg_id, chunk_idx, total_chunks, len(encrypted_answer), username_str, group_id)
                        encrypted_header = cipher.aes_encrypt(header)
                        msg_AES = encrypted_header + encrypted_answer
                        client_socket.send(msg_AES)
                          
        except (ConnectionResetError, BrokenPipeError, ConnectionError, OSError):
            client_socket.close()
            client_connected = False
            self.clients_currently_on -= 1
            if is_in_set:
                self.users_set.discard(name)
            return
                    #self.clients_list.append((client_socket, cipher))


        if client_in:     #למקרה והexcpet לא מוציא את התרד 
            try:
                data = client_socket.recv(11)

                if not data:
                    raise ConnectionError
                else:
                    print(cipher.aes_decrypt(data).decode())
            except (ConnectionResetError, BrokenPipeError, ConnectionError, OSError):
                client_socket.close()
                client_connected = False
                self.clients_currently_on -= 1
                self.users_set.discard(name)

                return

        #    '''
            with self.temp_recconect_dic_lock:
                self.temp_recconect_dic[name] = {"queue": Queue(), "msg_ids": set()}
            queue_for_client = Queue()
            sending_q_client_thread = threading.Thread(target = self.Send_Client_By_Q, args=(queue_for_client, client_socket, socket_lock, ack_evnt))
            sending_q_client_thread.start()
            
            print(f"retriving msgs for {name} that were not sent while offline")
            msgs = DB_object.Recv_Messages_Not_Sent_To_Client(name)

            if not msgs:
                print(f"no msgs for {name}")
            else:
                for msg in msgs:
                    if msg[0] != "wav":
                        header = msg[4]
                        data_bytes = msg[5]
                        header_AES_for_client = cipher.aes_encrypt(header)
                        data_AES_for_client = cipher.aes_encrypt(data_bytes)
                        msg_AES = header_AES_for_client + data_AES_for_client
                        try:
                            queue_for_client.put(msg_AES)
                        except (ConnectionResetError, BrokenPipeError, OSError):
                            client_socket.close()
                            client_connected = False
                            self.clients_currently_on -= 1
                            self.temp_recconect_dic.pop(name, None)
                            self.users_set.discard(name)
                            return


                    else:
                        data_bytes = msg[5]
                        voice_recording_bytes_len = len(data_bytes)
                        total_chunks = math.ceil(voice_recording_bytes_len/CHUNK_DATA_MAX_SIZE)
                        msg_id = msg[1]
                        username_str = msg[2]
                        group_id = msg[3]
                        counter = 0 
                        chunk_offset = 0
                        while counter < total_chunks:
                            chunk_bytes = data_bytes[chunk_offset:chunk_offset + CHUNK_DATA_MAX_SIZE]
                            chunk_bytes_len = len(chunk_bytes)
                            header = Pack_Header("wav", msg_id, counter + 1, total_chunks, chunk_bytes_len, username_str, group_id) #לא הוגדר מקודם, שלח עם groupid 0 מהsin sup ממקודם
                            header_AES = cipher.aes_encrypt(header)
                            chunk_data_AES = cipher.aes_encrypt(chunk_bytes)
                            msg_AES = header_AES + chunk_data_AES
                            #self.client_socket.send(voice_message_chunk_AES)
                            try:
                                queue_for_client.put(msg_AES)
                                chunk_offset += CHUNK_DATA_MAX_SIZE
                                counter += 1
                            except (ConnectionResetError, BrokenPipeError, OSError):
                                client_socket.close()
                                client_connected = False
                                self.clients_currently_on -= 1
                                self.temp_recconect_dic.pop(name, None)
                                self.users_set.discard(name)
                                return


                                                            
            time.sleep(0.5) # to try to prevent the case of the client reconnecting in the middle of receiving the wav message and the msg being put in the temp queue after the client has already received part of the message and thus not receiving the rest of the message because the server thinks it has already been sent to him while it was actually put in the temp queue after he reconnected
            while not self.temp_recconect_dic[name]["queue"].empty():
                header, msg = self.temp_recconect_dic[name]["queue"].get() # .split("|", 1) #
                header_AES_for_client = cipher.aes_encrypt(header)
                data_AES_for_client = cipher.aes_encrypt(msg)
                msg_AES = header_AES_for_client + data_AES_for_client
                try:
                    queue_for_client.put(msg_AES)
                    self.temp_recconect_dic[name]["queue"].task_done()

                except (ConnectionResetError, BrokenPipeError, OSError):
                    client_socket.close()
                    client_connected = False
                    self.clients_currently_on -= 1
                    with self.temp_recconect_dic_lock:
                        self.temp_recconect_dic.pop(name, None)
                    self.users_set.discard(name)
                    return


            with self.client_dic_lock:
                self.client_dic[name] = (queue_for_client, cipher)

            with self.temp_recconect_dic_lock:
                self.temp_recconect_dic.pop(name, None)
        #    '''
            '''
            self.client_dic[name] = (Queue(), cipher)
            sending_q_client_thread = threading.Thread(target = self.Send_Client_By_Q, args=(self.client_dic[name][0], client_socket, socket_lock, ack_evnt))
            sending_q_client_thread.start()
            '''
        while client_connected:
            try:
                header_encrypted= self.recv_exact(client_socket, HEADER_SIZE)
                header = cipher.aes_decrypt(header_encrypted)
                msg_type_str, msg_id, chunk_idx, total_chunks, payload_len, username_str, group_id = UnPack_Header(header)

                if msg_type_str == "str":
                    data_AES = self.recv_exact(client_socket, payload_len)
                    data_bytes = cipher.aes_decrypt(data_AES)
                    
                    '''
                    for key, value in self.client_dic.items():
                        if key != username_str:     #אפשר להוריד לבינתיים נראה לי    
                            data_AES_for_client = value[1].aes_encrypt(data_bytes)
                            header_AES_for_client = value[1].aes_encrypt(header)
                            msg_AES = header_AES_for_client + data_AES_for_client
                            value[0].put(msg_AES)
                    '''
                    if group_id == self.broadcast_id:
                        for key, value in self.client_dic.items():
                            if key != username_str:     #אפשר להוריד לבינתיים נראה לי    
                                data_AES_for_client = value[1].aes_encrypt(data_bytes)
                                header_AES_for_client = value[1].aes_encrypt(header)
                                msg_AES = header_AES_for_client + data_AES_for_client
                                value[0].put(msg_AES)
                        
                    else:

                        DB_object.Save_Message(msg_type_str, msg_id, username_str, group_id, header, data_bytes)
                        DB_object.Add_Users_To_connect_Messages_by_Group(msg_id, group_id)

                        for user in DB_object.Get_Group_Members(group_id, method = "list"):

                            if user not in self.client_dic:
                                print(f"{user} not online")
                                pass
                            else:
                                data_AES_for_client = self.client_dic[user][1].aes_encrypt(data_bytes)
                                header_AES_for_client = self.client_dic[user][1].aes_encrypt(header)
                                msg_AES = header_AES_for_client + data_AES_for_client
                                self.client_dic[user][0].put(msg_AES)

                elif msg_type_str == "wav":
                    chunk_data_AES = self.recv_exact(client_socket, payload_len)
                    chunk_data_bytes = cipher.aes_decrypt(chunk_data_AES)
                    if msg_id not in msg_id_dic:
                        msg_id_dic[msg_id] = {"vc_data": [], "total_chunks": total_chunks, "chunks_received": 0}
                    msg_id_dic[msg_id]["vc_data"].append(chunk_data_bytes)
                    msg_id_dic[msg_id]["chunks_received"] += 1

                    #client_socket.send(ack_msg_AES)
                    if msg_id_dic[msg_id]["chunks_received"] == msg_id_dic[msg_id]["total_chunks"]:

                        data_bytes = msg_id_dic[msg_id]["vc_data"]  
                        DB_object.Save_Message(msg_type_str, msg_id, username_str, group_id, header, data_bytes)
                        DB_object.Add_Users_To_connect_Messages_by_Group(msg_id, group_id)
                    '''
                    for key, value in self.client_dic.items():
                        if key != username_str:     #אפשר להוריד לבינתיים נראה לי    
                            chunk_data_AES_for_client = value[1].aes_encrypt(chunk_data_bytes)
                            header_AES_for_client = value[1].aes_encrypt(header)
                            msg_AES = header_AES_for_client + chunk_data_AES_for_client
                            value[0].put(msg_AES)
                    '''
                    if group_id == self.broadcast_id:
                        
                        for key, value in self.client_dic.items():
                            if key != username_str:     #אפשר להוריד לבינתיים נראה לי    
                                chunk_data_AES_for_client = value[1].aes_encrypt(chunk_data_bytes)
                                header_AES_for_client = value[1].aes_encrypt(header)
                                msg_AES = header_AES_for_client + chunk_data_AES_for_client
                                value[0].put(msg_AES)
                
                    else:
                        


                        for user in DB_object.Get_Group_Members(group_id, method = "list"):

                            if user not in self.client_dic:
                                with self.temp_recconect_dic_lock:
                                    if user in self.temp_recconect_dic:
                                        print(f"{user} is reconnecting, putting msg in temp queue")
                                        if msg_id not in self.temp_recconect_dic[user]["msg_ids"]:
                                            print(f"{user} connected middle of receiving wav message, putting msg in temp queue")
                                            self.temp_recconect_dic[user]["msg_ids"].add(msg_id)
                                            temp_counter = 1 #
                                            for chunk in msg_id_dic[msg_id]["vc_data"]:
                                                header_recconect = Pack_Header("wav", msg_id, temp_counter, total_chunks, len(chunk), username_str, group_id)
                                                temp_counter += 1
                                                #chunk = header_recconect + "|" + chunk #
                                                chunk = (header_recconect, chunk) #
                                                self.temp_recconect_dic[user]["queue"].put(chunk)
                                        else:
                                            #chunk = header + "|" + chunk_data_bytes 
                                            chunk = (header, chunk_data_bytes)
                                            self.temp_recconect_dic[user]["queue"].put(chunk)
                                            time.sleep(0.5) # to try to prevent the case of the client reconnecting in the middle of receiving the wav message and the msg being put in the temp queue after the client has already received part of the message and thus not receiving the rest of the message because the server thinks it has already been sent to him while it was actually put in the temp queue after he reconnected
                                    else:
                                        print(f"{user} not online")
                                    pass

                            else:
                                chunk_data_AES_for_client = self.client_dic[user][1].aes_encrypt(chunk_data_bytes)
                                header_AES_for_client = self.client_dic[user][1].aes_encrypt(header)
                                msg_AES = header_AES_for_client + chunk_data_AES_for_client
                                self.client_dic[user][0].put(msg_AES)

                elif msg_type_str == "crt":

                    data_AES = self.recv_exact(client_socket, payload_len)
                    data_bytes = cipher.aes_decrypt(data_AES)
                    data_str = data_bytes.decode()
                    group_name, usernames_str = data_str.split(",")
                    with self.group_id_counter_lock:
                        self.group_id_counter += 1
                        group_id_current = self.group_id_counter
                        did_create_group, log_answer = DB_object.Create_Group(group_id_current, usernames_str)
                        if did_create_group != True:
                            print("group id reverted")
                            self.group_id_counter -= 1
                    
                    print(f"tried to create group, db retured {log_answer}")

                    if did_create_group != True:
 
                        log_answer_bytes = log_answer.encode()
                        log_answer_len = len(log_answer_bytes)

                    elif did_create_group == True:
                        log_answer += group_name
                        log_answer_bytes = log_answer.encode()
                        log_answer_len = len(log_answer_bytes)

                    header = Pack_Header("ans", msg_id, chunk_idx, total_chunks, log_answer_len, username_str, group_id)
                    DB_object.Save_Message("ans", msg_id, username_str, group_id, header, log_answer_bytes)


                    if log_answer.split("|")[0] == "At least one user does not exist ":
                        print("server log - entered send")
                        
                        DB_object.Add_User_To_connect_Messages(msg_id, username_str)

                        header_AES_return = cipher.aes_encrypt(header)
                        log_answer_AES = cipher.aes_encrypt(log_answer.encode())
                        msg_AES = header_AES_return + log_answer_AES
                        
                        if username_str in self.client_dic:
                           self.client_dic[username_str][0].put(msg_AES)
                        else:
                            print(f"{username_str} is not online")
                    else:
                        for user in DB_object.Get_Group_Members(group_id_current, method = "list"):
                            
                            DB_object.Add_User_To_connect_Messages(msg_id, user)

                            if user not in self.client_dic:
                                print(f"{user} is not online")
                            
                            else:
                                header_AES_for_client = self.client_dic[user][1].aes_encrypt(header)

                                log_answer_AES = self.client_dic[user][1].aes_encrypt(log_answer_bytes)


                                msg_AES = header_AES_for_client + log_answer_AES

                                self.client_dic[user][0].put(msg_AES)
                    '''
                    header_AES_return = cipher.aes_encrypt(header)
                    log_answer_AES = cipher.aes_encrypt(log_answer.encode())
                    msg_AES = header_AES_return + log_answer_AES
                    self.client_dic[username_str][0].put(msg_AES)
                    '''
                elif msg_type_str == "add":
                    data_AES = self.recv_exact(client_socket, payload_len)
                    data_bytes = cipher.aes_decrypt(data_AES)
                    data_str = data_bytes.decode()

                    target_group_id, target_username, group_name_for_added_user = data_str.split("|")
                    with self.edit_group_lock:
                        did_work, log_answer = DB_object.Add_To_Group(target_group_id, target_username)
                    
                    print("entered if")

                    if did_work:  # -----
                        print("entered did work")
                        log_answer += f" |add.{target_group_id}.{target_username}"
                    else:
                        print("entered did not work")
                        log_answer += f" |"
                    
                    print(log_answer)

                    log_answer_bytes = log_answer.encode()
                    log_answer_AES = cipher.aes_encrypt(log_answer_bytes)
                    log_answer_len = len(log_answer_AES)

                    header = Pack_Header("ans", msg_id, chunk_idx, total_chunks, log_answer_len, username_str, group_id)
                    header_AES = cipher.aes_encrypt(header)

                    print(log_answer)

                    if not did_work:
                        if username_str in self.client_dic:
                            msg_AES = header_AES + log_answer_AES
                            self.client_dic[username_str][0].put(msg_AES)
                        else:
                            print(f"{username_str} is not online")

                    else:
                        DB_object.Save_Message("ans", msg_id, username_str, group_id, header, log_answer_bytes)
                        
                        msg_id_tu = Generate_msg_id()
                        log_answer_tu = DB_object.Give_Add_Group_Message_To_Added(target_group_id, group_name_for_added_user)
                        log_answer_bytes_tu = log_answer_tu.encode()
                        log_answer_len_tu = len(log_answer_bytes_tu)

                        header_tu = Pack_Header("ans", msg_id_tu, chunk_idx, total_chunks, log_answer_len_tu, username_str, group_id)

                        DB_object.Save_Message("ans", msg_id_tu, username_str, group_id, header_tu, log_answer_bytes_tu)

                        for user in DB_object.Get_Group_Members(target_group_id, method = "list"):
                            
                            if user == target_username:
                                DB_object.Add_User_To_connect_Messages(msg_id_tu, target_username)
                            else:
                                DB_object.Add_User_To_connect_Messages(msg_id, user)

                            if user not in self.client_dic:
                                print (f"{user} is not online")

                            elif user == target_username:
                                
                               
                                log_answer_AES_tu = self.client_dic[user][1].aes_encrypt(log_answer_bytes_tu)

                                header_AES_tu = self.client_dic[user][1].aes_encrypt(header_tu)

                                msg_AES_tu = header_AES_tu + log_answer_AES_tu

                                self.client_dic[user][0].put(msg_AES_tu)

                            else:
                                log_answer_AES = self.client_dic[user][1].aes_encrypt(log_answer_bytes)

                                header_AES = self.client_dic[user][1].aes_encrypt(header)
                                
                                msg_AES = header_AES + log_answer_AES

                                self.client_dic[user][0].put(msg_AES)

                elif msg_type_str == "rmv":
                    data_AES = self.recv_exact(client_socket, payload_len)
                    data_bytes = cipher.aes_decrypt(data_AES)
                    data_str = data_bytes.decode()

                    target_group_id, target_username, group_name_for_removed_user = data_str.split("|")
                    with self.edit_group_lock:
                        did_work, log_answer = DB_object.Remove_From_Group(target_group_id, target_username)
                     
                    if did_work: # -----
                        log_answer += f" |rmv.{target_group_id}.{target_username}"
                    else:
                        log_answer += f" |"

                    log_answer_bytes = log_answer.encode()
                    log_answer_AES = cipher.aes_encrypt(log_answer_bytes)
                    log_answer_len = len(log_answer_AES)

                    header = Pack_Header("ans", msg_id, chunk_idx, total_chunks, log_answer_len, username_str, group_id)
                    header_AES = cipher.aes_encrypt(header)

                    print(log_answer)

                    if not did_work:
                        if username_str in self.client_dic:
                            msg_AES = header_AES + log_answer_AES
                            self.client_dic[username_str][0].put(msg_AES)
                        else:
                            print(f"{username_str} is not online")

                    else:

                        DB_object.Save_Message("ans", msg_id, username_str, group_id, header, log_answer_bytes)

                        msg_id_tu = Generate_msg_id()
                        log_answer_tu = DB_object.Give_Remove_Group_Message_To_Removed(target_group_id, group_name_for_removed_user)
                        log_answer_bytes_tu = log_answer_tu.encode()
                        log_answer_len_tu = len(log_answer_bytes_tu)

                        header_tu = Pack_Header("ans", msg_id_tu, chunk_idx, total_chunks, log_answer_len_tu, username_str, group_id)

                        DB_object.Save_Message("ans", msg_id_tu, username_str, group_id, header_tu, log_answer_bytes_tu)

                        DB_object.Add_User_To_connect_Messages(msg_id_tu, target_username)

                        if target_username in self.client_dic:
                            
                            
                            log_answer_AES_tu = self.client_dic[target_username][1].aes_encrypt(log_answer_bytes_tu)

                            header_AES_tu = self.client_dic[target_username][1].aes_encrypt(header_tu)

                            msg_AES_tu = header_AES_tu + log_answer_AES_tu

                            self.client_dic[target_username][0].put(msg_AES_tu)
                        else:
                            print(f"{target_username} is not online")


                        for user in DB_object.Get_Group_Members(target_group_id, method = "list"):
                            
                            DB_object.Add_User_To_connect_Messages(msg_id, user)

                            if user not in self.client_dic:
                                print (f"{user} is not online")

                            else:
                                log_answer_AES = self.client_dic[user][1].aes_encrypt(log_answer_bytes)

                                header_AES = self.client_dic[user][1].aes_encrypt(header)
                                
                                msg_AES = header_AES + log_answer_AES

                                self.client_dic[user][0].put(msg_AES)

                    #if not did_work:
                    #rememeber to add group_name to message to added client    
                elif msg_type_str == "ack":
                    if chunk_idx == total_chunks:
                        print(f"received ACK for complete message {msg_id} from {username_str}")
                        DB_object.Update_Connect_Message_Status(msg_id, username_str)
                    ack_evnt.set()
                    continue

                ack_msg = Generate_ACK_msg(msg_id, username_str, chunk_idx, total_chunks, group_id)
                ack_msg_AES = cipher.aes_encrypt(ack_msg)
                with socket_lock:
                    client_socket.send(ack_msg_AES)    

                    
                    #for i, chunk in enumerate(data_bytes):
                    #    print(f"Chunk {i}: {chunk}")
                    '''
                    arrays = [np.frombuffer(chunk, dtype=np.float32) for chunk in data_bytes]

                    
                    # מחברים את כל הצ'אנקים למערך רציף אחד
                    full_audio = np.concatenate(arrays)

                    # שם הקובץ כולל index
                    filename = self.audio_dir / f"recording{msg_id}.wav"
                    
                    # שומרים את הקובץ
                    sf.write(filename, full_audio, 44100)
                    print("Saved WAV:", filename)

                    del msg_id_dic[msg_id]
                    '''                


                    continue
                
            except(ConnectionResetError, BrokenPipeError, ConnectionError, OSError): #except (socket.timeout, ConnectionResetError, BrokenPipeError):
                with self.client_dic_lock:
                #    for name in list(self.client_dic.keys()):
                #        if client_disconnected(name):
                            del self.client_dic[name]
                #stop_q.set()
                self.clients_currently_on -=1
                client_connected = False
                client_socket.close()
                msg_id_dic.clear()
                self.users_set.discard(name)

                break
            '''
            if client_ping_bytes == data_in_bytes_From_One:
                #print("true")
                continue
            elif client_ping_bytes in data_in_bytes_From_One:
                data_in_bytes_From_One = data_in_bytes_From_One.removeprefix(client_ping_bytes)
                data_in_bytes_From_One = data_in_bytes_From_One.removesuffix(client_ping_bytes)
            
            for client_list_socket, cipher_list in self.clients_list:
                if client_list_socket == client_socket:
                    continue
                data_in_Aes_For_All = cipher_list.aes_encrypt(data_bytes)
                header_in_Aes_For_All = cipher_list.aes_encrypt(header)
                #print("False")
                msg_for_all_AES = header_in_Aes_For_All + data_in_Aes_For_All
                client_list_socket.send(msg_for_all_AES) 
            '''
Server()

'''
                meta_data_and_data_AES_From_One=client_socket.recv(1024)
                meta_data_AES = meta_data_and_data_AES_From_One[:9]
                meta_data_bytes = cipher.aes_decrypt(meta_data_AES)
                meta_data_type_bytes, meta_data_len_int = meta_data_bytes[:5], int.from_bytes(meta_data_bytes[5:], 'big')
                data_AES_From_One = meta_data_and_data_AES_From_One[9:]
                data_in_bytes_From_One = cipher.aes_decrypt(data_AES_From_One)
                data_in_str_From_One = data_in_bytes_From_One.decode()
'''
