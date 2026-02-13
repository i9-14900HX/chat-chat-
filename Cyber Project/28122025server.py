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

class Server:
    def __init__(self):
        self.file_path = Path(__file__).resolve()
        self.folder_path = self.file_path.parent
        self.audio_dir = self.folder_path / "audio_recordings_wav"
        self.audio_dir.mkdir(parents=True, exist_ok=True)
        self.audio_dir_str = str(self.audio_dir)
        self.username_password_salt_db = str(self.folder_path / "username_password_salt_db.db")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('127.0.0.1', 6666))
        server.listen(100) 
        print("server on...")
        self.clients_currently_on = 0
        self.broadcast_id = 0
        #self.clients_list = []
        self.client_dic = {}
        self.place_holder_key = "place_holder_key"
        temporary_db_object = DB_file.DB_Class_General()
        self.group_id_counter = temporary_db_object.Get_Current_Group_Id()
        self.sup_lock = threading.Lock()
        self.client_dic_lock = threading.Lock()
        self.group_id_counter_lock = threading.Lock()
        self.add_group_lock = threading.Lock()
        
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
            shared_key = Cipher.get_dh_shared_key(dh, client_pk)
            print("shared key:", shared_key)
            client_socket.send(pk)
            cipher = Cipher(shared_key, NONCE)
            while not client_in:
                header_encrypted= self.recv_exact(client_socket, HEADER_SIZE)
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
            return
                    #self.clients_list.append((client_socket, cipher))


        if client_in:     #למקרה והexcpet לא מוציא את התרד         
            self.client_dic[name] = (Queue(), cipher)
            sending_q_client_thread = threading.Thread(target = self.Send_Client_By_Q, args=(self.client_dic[name][0], client_socket, socket_lock, ack_evnt))
            sending_q_client_thread.start()
        
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
                        DB_object.Save_audio_bytes_in_dir(data_bytes, msg_id)   
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

                    if log_answer.split("|")[0] == "At least one user does not exist ":
                        print("server log - entered send")
                        
                        header_AES_return = cipher.aes_encrypt(header)
                        log_answer_AES = cipher.aes_encrypt(log_answer.encode())
                        msg_AES = header_AES_return + log_answer_AES
                        self.client_dic[username_str][0].put(msg_AES)
                        
                    else:
                        for user in DB_object.Get_Group_Members(group_id_current, method = "list"):

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
                    with self.add_group_lock:
                        did_work, log_answer = DB_object.Add_To_Group(target_group_id, target_username)
                    
                    log_answer += f" |add.{target_group_id}.{target_username}"
                    log_answer_bytes = log_answer.encode()
                    log_answer_AES = cipher.aes_encrypt(log_answer_bytes)
                    log_answer_len = len(log_answer_AES)

                    header = Pack_Header("ans", msg_id, chunk_idx, total_chunks, log_answer_len, username_str, group_id)
                    header_AES = cipher.aes_encrypt(header)

                    print(log_answer)

                    if not did_work:
                        msg_AES = header_AES + log_answer_AES
                        self.client_dic[username_str][0].put(msg_AES)

                    else:
                        for user in DB_object.Get_Group_Members(target_group_id, method = "list"):

                            if user not in self.client_dic:
                                print (f"{user} is not online")

                            elif user == target_username:
                                log_answer_tu = DB_object.Give_Add_Group_Message_To_Added(target_group_id, group_name_for_added_user)
                                log_answer_bytes_tu = log_answer_tu.encode()
                                log_answer_AES_tu = self.client_dic[user][1].aes_encrypt(log_answer_bytes_tu)
                                log_answer_len_tu = len(log_answer_AES_tu)

                                header_tu = Pack_Header("ans", msg_id, chunk_idx, total_chunks, log_answer_len_tu, username_str, group_id)
                                header_AES_tu = self.client_dic[user][1].aes_encrypt(header_tu)

                                msg_AES_tu = header_AES_tu + log_answer_AES_tu

                                self.client_dic[user][0].put(msg_AES_tu)

                            else:
                                log_answer_AES = self.client_dic[user][1].aes_encrypt(log_answer_bytes)

                                header_AES = self.client_dic[user][1].aes_encrypt(header)
                                
                                msg_AES = header_AES + log_answer_AES

                                self.client_dic[user][0].put(msg_AES)

                    #if not did_work:
                    #rememeber to add group_name to message to added client    
                elif msg_type_str == "ack":
                    ack_evnt.set()
                    continue

                ack_msg = Generate_ACK_msg(msg_id, username_str)
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
                
            except(ConnectionResetError, BrokenPipeError): #except (socket.timeout, ConnectionResetError, BrokenPipeError):
                with self.client_dic_lock:
                #    for name in list(self.client_dic.keys()):
                #        if client_disconnected(name):
                            del self.client_dic[name]
                #stop_q.set()
                self.clients_currently_on -=1
                client_connected = False
                client_socket.close()
                msg_id_dic.clear()
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
