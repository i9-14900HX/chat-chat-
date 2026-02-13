from pathlib import Path
import sqlite3
import hashing 
import numpy as np
import soundfile as sf
import threading

class DB_Class_General:
    def __init__(self):
        #השגת תיקייה מריצה
        self.file_path = Path(__file__).resolve()
        self.folder_path = self.file_path.parent

        self.audio_dir = self.folder_path / "audio_recordings_wav"
        self.audio_dir.mkdir(parents=True, exist_ok=True)
        self.audio_dir_str = str(self.audio_dir)
        
        self.general_data_base = str(self.folder_path / "general_data_base.db") 
        DB_FILE = self.general_data_base 

        self.conn = sqlite3.connect(DB_FILE) 
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.commit()

        self.c = self.conn.cursor()
        
        self.c.execute('''CREATE TABLE IF NOT EXISTS users (username text, password text,salt text)''')
        self.conn.commit()
        
        self.c.execute('''CREATE TABLE IF NOT EXISTS messages (msg_id integer, username_str text ,group_id integer, header blob, content blob, users_nt_sent text)''')
        self.conn.commit()

        self.c.execute('''CREATE TABLE IF NOT EXISTS groups (group_id integer, usernames_str text)''')
        self.conn.commit()

        self.write_lock = threading.Lock()

    def save_user_and_pass(self, username, password):
        '''Saves the data from the user into the sql table
        that already exists'''
        print(username," ", password)
        print('hashing')
        hash_passwords=hashing.HashPasswords()
        salt, pw_hash = hash_passwords.hash_new_password(password)
        with self.write_lock:
            self.c.execute("INSERT INTO users VALUES (?,?,?)",(username, pw_hash,salt))
            self.conn.commit()

    def username_exist(self, username):
        '''Checks if the username exists in the sql table'''
        self.c.execute("SELECT username FROM users")
        results = self.c.fetchall()
        for r in results:
            if username == r[0]:
                return True
        return False

    def check_password(self, username, password):
        '''Checks if the password is correct'''
        self.c.execute("SELECT username,password,salt FROM users")
        results = self.c.fetchall()
        for r in results:
            # checks if the placement of the username and the password is right
            if username == r[0]:
                pw_hash=r[1]
                salt=r[2]
                hash_passwords=hashing.HashPasswords()
                if hash_passwords.is_correct_password(salt, pw_hash, password):
                    print('hashing password return true')
                    return True
        return False

    def print_table(self):
        '''Prints the table'''
        self.c.execute("SELECT * FROM users")
        print(self.c.fetchall())
        

    def Save_audio_bytes_in_dir(self, bytes_array, msg_id):
        arrays = [np.frombuffer(chunk, dtype=np.float32) for chunk in bytes_array]
        # מחברים את כל הצ'אנקים למערך רציף אחד
        full_audio = np.concatenate(arrays)
        # שם הקובץ כולל index
        filename = self.audio_dir / f"recording{msg_id}.wav"        
        # שומרים את הקובץ
        sf.write(filename, full_audio, 44100)
        print("Saved WAV:", filename)

    def Create_Group(self, group_id, usernames_str):

        usernames_list = [u for u in usernames_str.split("|") if u]
        did_create_group = False

        for username in usernames_list:
            if not self.username_exist(username):
                log_answer = "At least one user does not exist |"
                print(log_answer)
                return did_create_group, log_answer

        with self.write_lock:
            self.c.execute("INSERT INTO groups VALUES (?,?)",(group_id, usernames_str))
            self.conn.commit()  

        did_create_group = True

        log_answer = f"group created succesfuly |crt.{group_id}.{usernames_str}."
        print(log_answer)
        return did_create_group, log_answer
        
        
    def Get_Group_Members(self, group_id, method):

        self.c.execute("SELECT usernames_str FROM groups WHERE group_id = ?", (group_id,))
        row = self.c.fetchone()

        if not row or not row[0]:
            return []

        usernames_str = row[0]
        if method == "str":
            return usernames_str
        
        usernames_list = [u for u in usernames_str.split("|") if u]
        return usernames_list
    
    def Remove_From_Group(self, group_id, target_username):

        usernames_new = ""
        usernames_list = self.Get_Group_Members(group_id, method = "list")
        usernames_new = "|".join(u for u in usernames_list if u != target_username) + "|"

        with self.write_lock:
            self.c.execute("UPDATE groups SET usernames_str = ? WHERE group_id = ?",  (usernames_new, group_id))
            self.conn.commit()  
    
    def Add_To_Group(self, group_id, target_username):
        
        usernames_list = self.Get_Group_Members(group_id, method = "list")

        if not self.username_exist(target_username):
            return False, f"{target_username} does not exist"

        if target_username in usernames_list:
            return False, f"{target_username} already in group {group_id}"

        usernames_str = self.Get_Group_Members(group_id, method = "str")
        usernames_str_new = usernames_str + target_username + "|"

        with self.write_lock:
            self.c.execute("UPDATE groups SET usernames_str = ? WHERE group_id = ?",  (usernames_str_new, group_id))
            self.conn.commit()  

        return True, f"{target_username} succesfully added to {group_id}"
    
    def Get_Current_Group_Id(self):

        self.c.execute("SELECT COUNT(*) FROM groups")
        count = self.c.fetchone()[0]
        return count

    def Print_Group(self):

        self.c.execute("SELECT * FROM groups")
        print(self.c.fetchall())

    def Save_Message(self, msg_id, username_str, group_id, header, messagge):

        with self.write_lock:
            self.c.execute("INSERT INTO users VALUES (?,?,?,?,?,?)",(msg_id, username_str, group_id, header, messagge, "placeholder - who not sent to "))
            self.conn.commit()  

    #def Delete_Message(self, msg_id, username)
        

class DB_Class_Specific():
    def __init__(self, username):

        self.username = username
        self.write_lock = threading.Lock()
        #השגת תיקייה מריצה
        self.file_path = Path(__file__).resolve()
        self.folder_path = self.file_path.parent

        self.audio_dir = self.folder_path / f"audio_recordings_wav_{username}"
        self.audio_dir.mkdir(parents=True, exist_ok=True)
        self.audio_dir_str = str(self.audio_dir)
        
        self.specific_data_base = str(self.folder_path / f"specific_data_base_{username}.db") 
        DB_FILE = self.specific_data_base 

        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False, timeout = 30)    
        self.conn.execute("PRAGMA journal_mode=WAL;")
        
        self.conn.commit()


        self.c = self.conn.cursor()

        self.c.execute('''CREATE TABLE IF NOT EXISTS groups (group_id integer, usernames_str text, group_name text)''')
        self.conn.commit()

        #self.c.execute('''CREATE TABLE IF NOT EXISTS (username text, password text, salt text)''')
        #self.conn.commit()

    def Save_audio_bytes_in_dir(self, bytes_array, msg_id):
        
        arrays = [np.frombuffer(chunk, dtype=np.float32) for chunk in bytes_array]
        # מחברים את כל הצ'אנקים למערך רציף אחד
        full_audio = np.concatenate(arrays)
        # שם הקובץ כולל index
        filename = self.audio_dir / f"recording{msg_id}.wav"        
        # שומרים את הקובץ
        sf.write(filename, full_audio, 44100)
        print("Saved WAV:", filename)    
        
    def Create_Group(self, group_id, usernames_str, group_name):


        with self.write_lock:
            self.c.execute("INSERT INTO groups VALUES (?,?,?)",(group_id, usernames_str,group_name))
            self.conn.commit()  

        log_answer = f"group created succesfuly in client|crt.{group_id}.{usernames_str}.{group_name} "
        print(log_answer)
        
    def Get_Group_Members(self, group_id, method):

        self.c.execute("SELECT usernames_str FROM groups WHERE group_id = ?", (group_id,))
        row = self.c.fetchone()

        if not row or not row[0]:
            return []

        usernames_str = row[0]
        if method == "str":
            return usernames_str
        
        usernames_list = [u for u in usernames_str.split("|") if u]
        return usernames_list
    
    def Remove_From_Group(self, group_id, target_username):

        usernames_new = ""
        usernames_list = self.Get_Group_Members(group_id, method = "list")
        usernames_new = "|".join(u for u in usernames_list if u != target_username) + "|"

        with self.write_lock:
            self.c.execute("UPDATE groups SET usernames_str = ? WHERE group_id = ?",  (usernames_new, group_id))
            self.conn.commit()  
    
    def Add_To_Group(self, group_id, target_username):

        usernames_str = self.Get_Group_Members(group_id, method = "str")
        usernames_str_new = usernames_str + target_username + "|"

        with self.write_lock:
            self.c.execute("UPDATE groups SET usernames_str = ? WHERE group_id = ?",  (usernames_str_new, group_id))
            self.conn.commit()

    def Get_Group_Name_From_Id(self, group_id):
        
        self.c.execute("SELECT group_name FROM groups WHERE group_id = ?", (group_id,))
        row = self.c.fetchone()
        if row != None: 
            print(f"{row[0]} is match")
        else:
            print("nothing found in DB class")
        return row[0] if row is not None else None

    def Get_Group_Id_From_Name(self, group_name):

        self.c.execute("SELECT group_id FROM groups WHERE group_name = ?", (group_name,))
        row = self.c.fetchone()                
        if row != None: 
            print(f"{row[0]} is match")
        else:
            print("nothing found in DB class")
        return row[0] if row is not None else None
    
    def Is_Group_Exist(self, group_name):

        self.c.execute(
        "SELECT 1 FROM groups WHERE group_name = ?",
        (group_name.strip(),))

        return self.c.fetchone() is not None

    

    def Print_Group(self):

        self.c.execute("SELECT * FROM groups")
        print(self.c.fetchall())
