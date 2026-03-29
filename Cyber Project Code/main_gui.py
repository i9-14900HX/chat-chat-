import re
import sys
import threading

from PyQt6.QtWidgets import QApplication, QListWidget, QSizePolicy, QWidget, QPushButton, QLineEdit, QTextEdit, QLabel, QVBoxLayout, QMessageBox, QTableWidget, QMainWindow, QHBoxLayout, QComboBox, QListWidgetItem
from PyQt6.QtCore import QThread, QTime, QTimer, pyqtSignal, Qt
from PyQt6.QtGui import QTextCursor, QIcon, QPixmap, QTextCharFormat, QTextFormat

from clienttest import Client
from recorder_pyqt_gui import Recorder
import audio_player as ap
from DB_file import DB_Class_Specific
'''
class LoginGui(QWidget):
    def __init__(self):
        super().__init__()
        self.client = Client()
'''        
import sys
from PyQt6.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, 
                             QPushButton, QVBoxLayout, QHBoxLayout, QMessageBox)


class ClientWorker(QThread):
    sinup_singal = pyqtSignal(bool, str)
    # כאן תוכל להגדיר סיגנלים כדי לתקשר עם ה-GUI אם צריך
    def __init__(self, client, action, username, password, already_connected):
        super().__init__()
        self.client = client
        self.action = action
        self.username = username
        self.password = password
        self.already_connected = already_connected

    def run(self):
        try:
            # מתחברים לשרת רק אם אנחנו לא מחוברים כבר
            if not self.already_connected:
                self.client.Connect_To_Server()
            
            # מבצעים רק את ה-Auth (הלוגין/הרשמה)
            response = self.client.Get_in_Server(self.action, self.username, self.password)
            
            if response == "new user sign up complete":
                self.sinup_singal.emit(True, "נרשמת בהצלחה!")
            elif response == "You are In":
                self.sinup_singal.emit(True, "התחברת!")
                # כאן אפשר להמשיך ללוגיסטיקה אם צריך
            else:
                self.sinup_singal.emit(False, response)
                
        except Exception as e:
            self.sinup_singal.emit(False, f"שגיאה: {str(e)}")




class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.client = Client() 
        self.client_connected = False
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('כניסה והרשמה')
        self.setFixedSize(350, 250)

        # שדות קלט
        self.label_user = QLabel('שם משתמש:')
        self.input_user = QLineEdit()
        self.input_user.setPlaceholderText("הכנס שם משתמש")

        self.label_pass = QLabel('סיסמה:')
        self.input_pass = QLineEdit()
        self.input_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_pass.setPlaceholderText("הכנס סיסמה")

        # --- יצירת הכפתורים ---
        self.btn_login = QPushButton('התחבר')
        self.btn_register = QPushButton('הרשמה')
        
        # חיבור פונקציות לכפתורים
        self.btn_login.clicked.connect(lambda: self.handle_Start_sinup("sin"))
        self.btn_register.clicked.connect(lambda: self.handle_Start_sinup("sup"))

        # --- סידור הכפתורים בשורה אחת ---
        button_layout = QHBoxLayout() 
        button_layout.addWidget(self.btn_login)
        button_layout.addWidget(self.btn_register)

        # --- סידור כללי (אנכי) ---
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.label_user)
        main_layout.addWidget(self.input_user)
        main_layout.addWidget(self.label_pass)
        main_layout.addWidget(self.input_pass)
        
        # הוספת ה-layout של הכפתורים לתוך ה-layout הראשי
        main_layout.addLayout(button_layout) 

        self.setLayout(main_layout)

    def handle_Start_sinup(self, method):

        username = (self.input_user.text()).strip() # הסרת רווחים מיותרים
        password = (self.input_pass.text()).strip() # הסרת רווחים מיותרים
        
        if len(username) < 3 or len(username) > 16:
            QMessageBox.warning(self, 'שגיאה', 'אנא הזן שם משתמש בין 3 ל-16 תווים')
            return

        if not username.isalnum():
            QMessageBox.warning(self, 'שגיאה', 'שם המשתמש יכול להכיל רק אותיות ומספרים')
            return

        if len(password) < 3 or len(password) > 16:
            QMessageBox.warning(self, 'שגיאה', 'אנא הזן סיסמה בין 3 ל-16 תווים')
            return

        if not password.isalnum():
            QMessageBox.warning(self, 'שגיאה', 'הסיסמה יכולה להכיל רק אותיות ומספרים')
            return

        self.btn_login.setEnabled(False)
        self.btn_register.setEnabled(False)
        
        self.worker = ClientWorker(self.client, method, username, password, self.client_connected)
        self.worker.sinup_singal.connect(self.on_finished)
        self.client_connected = True
        # 4. הפעלה! (זה מריץ את ה-run של ה-Worker בת'רד נפרד)
        self.worker.start()
    
    def on_finished(self, success, message):
        """הפונקציה שרצה כשה-Worker מסיים (בגלל ה-Signal)"""
        # החזרת הכפתורים למצב פעיל
        self.btn_login.setEnabled(True)
        self.btn_register.setEnabled(True)

        if success:
            if "נרשמת" in message:
                QMessageBox.information(self, "הצלחה", message)
            else:
                QMessageBox.information(self, "הצלחה", message)
                self.client.username = self.input_user.text()
                
                # הפעלת הת'רדים של הקליינט (recv_data_from_server וכו')
                
                # פתיחת חלון הצ'אט והעברת הקליינט אליו
                self.chat_win = ChatWindow(self.client)
                self.chat_win.show()
                
                self.close()
                # כאן תוכל לפתוח את החלון הבא של האפליקציה!
                # self.open_main_app() 
        else:
             QMessageBox.critical(self, "שגיאה", message)
'''             
class RetriveGroupInfo(QThread):
    group_info_signal = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.DB = DB_Class_Specific()

    def run(self):
        group_id_and_name_list = self.DB.Get_Groups()
'''
    
class ChatWindow(QWidget):
    def __init__(self, client):
        super().__init__()
        self.client = client
        self.username = self.client.username

        self.recorder = None
        
        self.audio_state = "idle" # מצבים: idle (רגיל), recording (מקליט), recorded (סיים להקליט)

        self.DB_reader = DB_Class_Specific(self.username)

        self.audio_player_object = ap.Audio_player() # האובייקט שלך
        self.current_playing_button = None

        self.record_timer = QTimer()
        self.record_timer.timeout.connect(self.update_timer_display)
        self.elapsed_time = QTime(0, 0, 0)

        self.in_group_gui = 0 
        self.init_ui()
        


        self.client.new_serversays_signal.connect(self.show_Server_says)

        self.client.new_in_group.connect(self.crt_group_gui)
        self.client.new_add_group.connect(self.add_group_gui)
        self.client.new_remv_group.connect(self.remv_group_gui)

        self.client.Start_Client() 

    def init_ui(self):
        self.setWindowTitle(f"audio chat- {self.client.username}")
        self.resize(800, 600)
        
        # === לייאאוט ראשי: מחלק את המסך לימין (קבוצות) ושמאל (אזור הצ'אט) ===
        main_layout = QHBoxLayout()
        
        '''
        right_panel_layout = QVBoxLayout()  #*

        self.input_new_group_name = QLineEdit() #*
        self.input_new_group_name.setPlaceholderText("הכנס שם קבוצה...") #*
        
        self.input_new_group_members = QLineEdit() #*
        self.input_new_group_members.setPlaceholderText("הכנס חברי קבוצה (מופרדים ברווח)...") #*
        
        self.btn_create_group = QPushButton("צור קבוצה") #*
        self.btn_create_group.clicked.connect(self.create_group_logic) # חיבור לפונקציית יצירה #*

        # --- צד ימין: רשימת קבוצות ---
        self.groups_list = QListWidget()
        self.groups_list.setFixedWidth(220)
        # חיבור לחיצה על קבוצה לפונקציה
        self.groups_list.itemClicked.connect(self.on_group_selected)

        right_panel_layout.addWidget(QLabel("<b>יצירת קבוצה חדשה:</b>")) #*
        right_panel_layout.addWidget(self.input_new_group_name) #*
        right_panel_layout.addWidget(self.input_new_group_members) #*
        right_panel_layout.addWidget(self.btn_create_group) #*
        right_panel_layout.addSpacing(10) # רווח קטן בין היצירה לרשימה #*
        right_panel_layout.addWidget(QLabel("<b>הקבוצות שלי:</b>")) #*
        right_panel_layout.addWidget(self.groups_list) #*
        '''
        right_panel_layout = QVBoxLayout()
        right_panel_layout.setSpacing(5) # רווח קטן בין האלמנטים
        right_panel_layout.setContentsMargins(10, 0, 10, 0) # שוליים פנימיים
        
        # הגדרת רוחב אחיד לכולם
        fixed_width = 220

        # 1. אזור יצירת קבוצה חדשה
        create_label = QLabel("<b>יצירת קבוצה חדשה:</b>")
        create_label.setFixedWidth(fixed_width)
        
        self.input_new_group_name = QLineEdit()
        self.input_new_group_name.setPlaceholderText("הכנס שם קבוצה...")
        self.input_new_group_name.setFixedWidth(fixed_width)
        
        self.input_new_group_members = QLineEdit()
        self.input_new_group_members.setPlaceholderText("חברי קבוצה (מופרדים ברווח)...")
        self.input_new_group_members.setFixedWidth(fixed_width)
        self.input_new_group_members.setMaxLength(160) # הגבלת אורך הקלט (אופציונלי)


        self.btn_create_group = QPushButton("צור קבוצה")
        self.btn_create_group.setFixedWidth(fixed_width)
        self.btn_create_group.clicked.connect(self.create_group_logic)
        
        # 2. רשימת הקבוצות
        list_label = QLabel("<b>הקבוצות שלי:</b>")
        list_label.setFixedWidth(fixed_width)
        
        self.groups_list = QListWidget()
        self.groups_list.setFixedWidth(fixed_width)
        
        # כאן השינוי החשוב:
        # אנחנו אומרים לרשימה להתרחב אנכית ככל האפשר
        self.groups_list.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        
        self.groups_list.itemClicked.connect(self.on_group_selected)

        self.load_group_data()

        # הוספת האלמנטים
        right_panel_layout.addWidget(create_label)
        right_panel_layout.addWidget(self.input_new_group_name)
        right_panel_layout.addWidget(self.input_new_group_members)
        right_panel_layout.addWidget(self.btn_create_group)
        
        right_panel_layout.addSpacing(20)
        
        right_panel_layout.addWidget(list_label)
        right_panel_layout.addWidget(self.groups_list)
        # --- צד שמאל: אזור הצ'אט ---
        chat_layout = QVBoxLayout()
        
        # 1. למעלה: בר עליון (משמאל לימין)
        top_bar_layout = QHBoxLayout()
        self.lbl_group_name = QLabel("בחר קבוצה...")
        self.combo_members = QComboBox()
        self.input_target_user = QLineEdit()
        self.input_target_user.setPlaceholderText("שם משתמש...")
        self.input_target_user.setMaxLength(16)
        self.btn_add = QPushButton("הוסף")
        self.btn_add.clicked.connect(lambda: self.add_rmv_user("ADD"))
        self.btn_remove = QPushButton("הוצא")
        self.btn_remove.clicked.connect(lambda: self.add_rmv_user("RMV"))
        top_bar_layout.addWidget(self.lbl_group_name)
        top_bar_layout.addWidget(self.combo_members)
        top_bar_layout.addWidget(self.input_target_user)
        top_bar_layout.addWidget(self.btn_add)
        top_bar_layout.addWidget(self.btn_remove)
        
        # 2. אמצע: תצוגת ההודעות
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        
        # 3. למטה: אזור הקלדה וכפתורי שליחה/הקלטה
        bottom_bar_layout = QHBoxLayout()
        self.input_msg = QLineEdit()
        self.input_msg.setPlaceholderText("הקלד הודעה...")
        self.input_msg.setMaxLength(670)
        self.input_msg.textChanged.connect(self.on_text_changed) # מאזין לשינויים בטקסט
        
        self.lbl_timer = QLabel("00:00")
        self.lbl_timer.setStyleSheet("color: red; font-weight: bold; font-size: 16px;")
        self.lbl_timer.hide() # מוסתר כברירת מחדל

        self.btn_delete_audio = QPushButton("מחק")
        self.btn_delete_audio.hide() # מוסתר כברירת מחדל
        self.btn_delete_audio.clicked.connect(self.cancel_audio)
        
        self.btn_action = QPushButton("הקלט")
        self.btn_action.clicked.connect(self.handle_action_click)
        
        bottom_bar_layout.addWidget(self.input_msg)
        bottom_bar_layout.addWidget(self.lbl_timer)
        bottom_bar_layout.addWidget(self.btn_delete_audio)
        bottom_bar_layout.addWidget(self.btn_action)
        
        # חיבור כל החלקים של אזור הצ'אט
        chat_layout.addLayout(top_bar_layout)
        chat_layout.addWidget(self.chat_display)
        chat_layout.addLayout(bottom_bar_layout)
        
        # הוספת אזור הצ'אט ורשימת הקבוצות ללייאאוט הראשי
        main_layout.addLayout(chat_layout)  # צד שמאל
        #main_layout.addWidget(self.groups_list) # צד ימין
        main_layout.addLayout(right_panel_layout) #*
        self.setLayout(main_layout)

        self.no_group_ui_change()
        


    # ==========================================
    # לוגיקה של ממשק המשתמש (כפתור דינמי)
    # ==========================================
    def no_group_ui_change(self):
        self.in_group_gui = 0
        self.lbl_group_name.setText("בחר קבוצה...")
        self.btn_add.setEnabled(False)
        self.btn_remove.setEnabled(False)
        self.input_target_user.setEnabled(False)
        self.input_msg.setEnabled(False)
        self.btn_action.setEnabled(False)
        self.combo_members.clear()
        self.lbl_timer.hide()
        self.btn_delete_audio.hide()
        self.chat_display.clear()

    def load_group_data(self):
        id_and_name_list = self.DB_reader.Get_Groups()

        if not id_and_name_list:
            return
        
        for group_id, group_name in id_and_name_list:
            item = QListWidgetItem(group_name)
            item.setData(Qt.ItemDataRole.UserRole, group_id) # שמירת ה-ID בתוך האובייקט
            self.groups_list.addItem(item)

    def on_text_changed(self, text):
        """פועל בכל פעם שהמשתמש מקליד או מוחק תו"""
        if self.audio_state != "idle":
            return # אם אנחנו באמצע הקלטה, לא משנים את הכפתור בגלל טקסט

        if text.strip(): # אם יש טקסט
            self.btn_action.setText("שלח")
        else: # אם תיבת הטקסט ריקה
            self.btn_action.setText("הקלט")

    def update_timer_display(self):
        self.elapsed_time = self.elapsed_time.addSecs(1)
        self.lbl_timer.setText(self.elapsed_time.toString("mm:ss"))

        if self.elapsed_time >= QTime(0, 10, 0):
            print("הזמן נגמר! עוצר הקלטה אוטומטית...")
            self.audio_state = "recorded"
            self.record_timer.stop()
            self.btn_action.setText("שלח הקלטה")
            self.btn_action.setEnabled(False) # ננעל את כפתור השליחה עד לקבלת המידע מההקלטה
            self.btn_delete_audio.show() # חושף את כפתור ה"מחק"
            QMessageBox.information(self, "הודעה", "הגעת למקסימום זמן ההקלטה (10 דקות), ההקלטה נעצרה אוטומטית.")
            # כאן תקרא לפונקציית עצירת ההקלטה של הקליינט שלך!

            self.recorder.End_Recording()

    def handle_action_click(self):
        """פועל כשהמשתמש לוחץ על הכפתור הראשי (שלח/הקלט/עצור)"""
        action = self.btn_action.text()
        
        if action == "שלח":
            self.send_text_message()
            
        elif action == "הקלט":
            self.audio_state = "recording"
            self.btn_action.setText("עצור הקלטה")
            self.input_msg.hide()      # העלמת תיבת הטקסט
            self.lbl_timer.show()     # הצגת הטיימר
            #self.input_msg.setEnabled(False) # נועל את תיבת הטקסט
            # כאן תקרא לפונקציית ההקלטה של הקליינט שלך!

            self.recorder = Recorder()
            # חיבור הסיגנל לפונקציה שתטפל במידע
            self.recorder.finished_recording.connect(self.handle_audio_data)

            self.record_thread = threading.Thread(target=self.recorder.Start_Recording, daemon=True)
            self.record_thread.start()

            self.elapsed_time = QTime(0, 0, 0)
            self.lbl_timer.setText("00:00")
            self.record_timer.start(1000)
            print("מתחיל הקלטה...") 
            
        elif action == "עצור הקלטה":
            self.audio_state = "recorded"
            self.record_timer.stop()
            self.btn_action.setText("שלח הקלטה")
            self.btn_action.setEnabled(False) # ננעל את כפתור השליחה עד לקבלת המידע מההקלטה
            self.btn_delete_audio.show() # חושף את כפתור ה"מחק"
            # כאן תקרא לפונקציית עצירת ההקלטה של הקליינט שלך!

            self.recorder.End_Recording() # זה יפעיל את הסיגנל עם המידע שהוקלט

            print("הקלטה נעצרה, מוכן לשליחה.")
            
        elif action == "שלח הקלטה":
            #self.client.Send_Audio(self.audio_bytes)
            # כאן תשלח את האודיו דרך הקליינט!
            in_group = self.in_group_gui # זה צריך להיות מעודכן לפי הקבוצה שנבחרה
            self.send_thread_audio = threading.Thread(target=self.client.send_server_recording, args=(self.audio_bytes, in_group), daemon=True)
            self.send_thread_audio.start()
            self.reset_audio_state()

    def handle_audio_data(self, audio_bytes):
        self.audio_bytes = audio_bytes
        self.btn_action.setEnabled(True) # מפעיל את כפתור השליחה עכשיו שיש לנו את המידע

    def cancel_audio(self):
        """פועל כשהמשתמש לוחץ על 'מחק' אחרי הקלטה"""
        self.audio_bytes = None
        print("מוחק הקלטה...")
        # כאן תנקה את המידע המוקלט בקליינט שלך
        self.reset_audio_state()

    def reset_audio_state(self):
        """מחזיר את הממשק למצב ההתחלתי של הקלדה/הקלטה"""
        self.audio_state = "idle"
        self.record_timer.stop()

        self.lbl_timer.hide()
        self.input_msg.show()

        self.btn_delete_audio.hide()
        self.input_msg.setEnabled(True)
        self.input_msg.clear()
        self.btn_action.setText("הקלט")

        self.audio_bytes = None # ניקוי המידע המוקלט מהזיכרון (אופציונלי, תלוי איך אתה מנהל את זה בקליינט)
         # יפעיל אוטומטית את on_text_changed ויחזיר ל"הקלט"

    # ==========================================
    # לוגיקה של ניווט ותקשורת עם ה-Client
    # ==========================================
    def create_group_logic(self):
        group_name = self.input_new_group_name.text().strip()
        members_text = self.input_new_group_members.text().strip()
        members_list = members_text.split(' ') if members_text else []
        
        
        if not group_name:
            QMessageBox.warning(self, "שגיאה", "אנא הזן שם קבוצה")
            return

        if not members_text:
            QMessageBox.warning(self, "שגיאה", "אנא הזן לפחות חבר קבוצה אחד")
            return

        if len(group_name) > 20:
            QMessageBox.warning(self, "שגיאה", "שם הקבוצה לא יכול להיות ארוך מ-20 תווים")
            return

        if not re.fullmatch(r'[a-zA-Z0-9א-ת ]+', group_name):
            QMessageBox.warning(self, "שגיאה", "שם הקבוצה מכיל תווים לא חוקיים")
            return

        if len(members_list) != len(set(members_list)):
            QMessageBox.warning(self, "שגיאה", "חברי הקבוצה לא יכולים להיות כפולים")
            return

        for member in members_list:
            if not member:
                QMessageBox.warning(self, "שגיאה", "אנא בדוק את מספר הרווחים בין שמות החברים")
                return
            if member == self.client.username:
                QMessageBox.warning(self, "שגיאה", "אין צורך להוסיף את עצמך כחבר בקבוצה")
                return
            
        self.set_group_creation_enabled(False)

        members_list.insert(0, self.client.username) # הוספת המשתמש עצמו לרשימת החברים (אופציונלי, תלוי איך אתה מנהל את זה בשרת)

        self.send_crt_gruop_thread = threading.Thread(target=self.client.Create_Group_Send_Server_Msg, args=(group_name, members_list), daemon=True)
        self.send_crt_gruop_thread.start()

        self.input_new_group_name.clear()
        self.input_new_group_members.clear()

        QTimer.singleShot(1000, lambda: self.set_group_creation_enabled(True))    
        # כאן תוכל להוסיף ולידציה נוספת על השמות (למשל, לבדוק אם הם קיימים בשרת)
    
    def add_rmv_user(self, task):
        group_id = self.in_group_gui

        user = self.input_target_user.text().strip()
        if not user:
            QMessageBox.warning(self, "שגיאה", "אנא הזן שם ")
            return
        if user == self.username and task == "ADD":
            QMessageBox.warning(self, "שגיאה", "אתה כבר נמצא בקבוצה")
            return
        if task == "ADD" and user in self.DB_reader.Get_Group_Members(group_id, method = "list"):
            if user == self.username:
                QMessageBox.warning(self, "שגיאה", "אתה כבר נמצא בקבוצה")
                return
            else:
                QMessageBox.warning(self, "שגיאה", f"{user} כבר נמצא בקבוצה")
                return
        if task == "RMV" and user not in self.DB_reader.Get_Group_Members(group_id, method = "list"):
            QMessageBox.warning(self, "שגיאה", f"{user} לא בקבוצה")
            return
        
        self.input_target_user.setEnabled(False)
        self.input_target_user.clear()

        if task == "ADD":
            self.add_rmv_user_thread = threading.Thread(target=self.client.Add_To_Group_Send_Server_Msg, args=(user, group_id), daemon=True)
        if task == "RMV":
            self.add_rmv_user_thread = threading.Thread(target=self.client.Remove_From_Group_Send_Server_Msg, args=(user, group_id), daemon=True)

        self.add_rmv_user_thread.start()
        QTimer.singleShot(100, lambda:self.input_target_user.setEnabled(True))

    def set_group_creation_enabled(self, status: bool):
        """נועלת או משחררת את כל אזור יצירת הקבוצה"""
        self.input_new_group_name.setEnabled(status)
        self.input_new_group_members.setEnabled(status)
        self.btn_create_group.setEnabled(status)

        # כאן תוכל לקרוא לפונקציית יצירת הקבוצה של הקליינט שלך, למשל:
        # self.client.Create_Group(group_name, members)
        # ואם זה מצליח, תוכל להוסיף את הקבוצה לרשימה:
        # self.groups_list.addItem(group_name)

    
    def on_group_selected(self, item):
        self.groups_list.setEnabled(False)
        QTimer.singleShot(250, lambda: self.groups_list.setEnabled(True))
        '''
        #self.client.in_group =  # עדכון הקבוצה הנוכחית בקליינט
        # --- self.in_group_gui =
        group_name = item.text()
        self.lbl_group_name.setText(group_name)
        # --- self.combo_members.clear()
        # --- self.combo_members.addItems(self.client.Get_Group_Members(group_name)) # פונקציה שתחזיר את רשימת החברים בקבוצה מהקליינט
        self.chat_display.clear()
        # כאן תוכל לבקש מהקליינט לשלוף את ההיסטוריה של הקבוצה מה-DB
        # ולשנות את self.client.in_group ל-ID של הקבוצה שנבחרה
        '''
        group_id = item.data(Qt.ItemDataRole.UserRole)

        if group_id == self.in_group_gui:
            print("same group")
            return
        
        if self.recorder:
            try:
                self.recorder.Force_close()
            except:
                pass

        self.reset_audio_state()    

        group_name = item.text()
    # שליפת ה-ID ששמרנו ב-UserRole (או חיפוש ב-DB לפי שם)
        
        self.in_group_gui = group_id

        self.lbl_group_name.setText(f"{group_name}")
        
        # שחרור כפתורים שננעלו ב-no_group_ui_change
        self.input_msg.setEnabled(True)
        self.btn_action.setEnabled(True)
        self.input_target_user.setEnabled(True)
        self.btn_add.setEnabled(True)
        self.btn_remove.setEnabled(True)
        
        self.input_msg.clear()
        self.input_target_user.clear()
        
        # טעינת היסטוריה מה-DB
        
        self.combo_members.clear()

        this_list = self.DB_reader.Get_Group_Members(group_id, method = "list")
        for user in this_list:
            if user == self.username:
                self.combo_members.insertItem(0, "you")
            else:
                self.combo_members.addItem(user)

        self.chat_display.clear()

        history = self.DB_reader.Get_Message_by_group(group_id)

        if not history:
            pass
        else:
            for msg_type, msg_id, user, g_id, data in history:
                if msg_type == "str":
                    time = self.format_msg_id(msg_id)
                    msg = f"{time} {user} sent: {data}"
                    if g_id == self.in_group_gui: 
                        self.chat_display.append(msg)
                if msg_type == "wav":
                    if g_id == self.in_group_gui: 
                        self.add_audio_message_to_gui(user, msg_id, g_id, data)

        

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
    
    def send_text_message(self):
        in_group = self.in_group_gui # זה צריך להיות מעודכן לפי הקבוצה שנבחרה
        text = self.input_msg.text()
        if text:
            print(f"שולח טקסט: {text}")

            # הוספה מקומית למסך (אופציונלי, תלוי אם אתה מחכה לאישור מהשרת)
            #self.chat_display.append(f"<b>אני:</b> {text}") 
            
            # קריאה לקליינט שלך
            # msg_aes = self.client.Client_string_message(text, self.client.in_group)
            # self.client.Send_Server_simple(msg_aes)
            
            self.input_msg.clear()
            self.send_thread = threading.Thread(target=self.client.Client_string_message, args=(text, in_group), daemon=True)
            self.send_thread.start()
        # כאן תוכל להוסיף את ה-UI של חלון הצ'אט שלך
    def add_message_to_gui(self, sender, msg_id, group_id, message):
        pass

    def add_audio_message_to_gui(self, sender, msg_id, group_id, filepath):
        """מוסיף הודעה קולית לצ'אט עם כפתור שמקושר לנתיב הקובץ ב-DB"""
        # בדיקה אם ההודעה שייכת לקבוצה שמוצגת כרגע
        if group_id != self.in_group_gui:
            return

        # 1. הוספת שם השולח וזמן (אופציונלי)
        time = self.format_msg_id(msg_id)
        self.chat_display.append(f"{time} {sender} sent: voice recording - ")
        
        # 2. יצירת הכפתור
        play_btn = QPushButton(" ▶ השמע הודעה ")
        play_btn.setFixedWidth(140)
        play_btn.setStyleSheet("""
            QPushButton { 
                background-color: #e1f5fe; 
                border-radius: 5px; 
                padding: 5px; 
                font-weight: bold;
            }
            QPushButton:hover { background-color: #b3e5fc; }
        """)

        # 3. חיבור הכפתור לפונקציית הניגון עם הנתיב מה-DB
        play_btn.clicked.connect(lambda: self.play_audio_logic(filepath))
        
        # 4. הכנסת הכפתור לתוך ה-QTextEdit בסוף הטקסט

        if group_id != self.in_group_gui:
            return

        '''
        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        #self.chat_display.setTextCursor(cursor)
        
        self.chat_display.setReadOnly(False)
        self.chat_display.addWidget(play_btn)
        
        self.chat_display.insertHtml("<br><br>") # רווח בין הודעות
        self.chat_display.setReadOnly(True)
        
        # גלילה אוטומטית להודעה החדשה
        self.chat_display.setTextCursor(cursor)
        self.chat_display.ensureCursorVisible()
        '''
        self.chat_display.setReadOnly(False)
        
        #cursor = self.chat_display.textCursor()
        #cursor.movePosition(QTextCursor.MoveOperation.End)
        
        # --- הטריק: יצירת Inline Widget בתוך הטקסט ---
        # משתמשים ב-layout של המסמך כדי להוסיף את הווידג'ט
        #self.chat_display.setTextCursor(cursor)
        
        # ב-PyQt6 הדרך הכי יציבה להוסיף ווידג'ט ל-QTextEdit היא זו:
        # אנחנו יוצרים "פורמט אובייקט" או פשוט משתמשים ב-insertWidget מה-cursor אם הייבוא נכון
        # אם ה-cursor.insertWidget נתן AttributeError קודם, זה בגלל גרסת ה-Qt.
        # הנה הפתרון העוקף:
        
        #cursor.insertText(" ") # רווח קטן לפני
        #self.chat_display.setReadOnly(False)
        
        # הוספת הכפתור כ-child של ה-chat_display
        #play_btn.setParent(self.chat_display) 
        
        # הזרקת ה-Widget למיקום הסמן
        #cursor.insertWidget(play_btn) 
        
        # ----------------------------------------
        #cursor = self.chat_display.textCursor()
        #cursor.movePosition(QTextCursor.MoveOperation.End)
    
    # זו הפקודה הקריטית - היא תעבוד אם ה-Import של QTextCursor תקין
        #cursor.insertWidget(play_btn)

        #self.chat_display.insertHtml("<br><br>") 
        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
    
    # הוספת הכפתור כ-Child של ה-Chat Display
        play_btn.setParent(self.chat_display)
    
    # פקודת הקסם של PyQt6:
    # במקום insertWidget של ה-Cursor, משתמשים בזה:
        self.chat_display.insertWidget(play_btn) 
    
    # ירידת שורה
        self.chat_display.append("")
        self.chat_display.setReadOnly(True)
        
        self.chat_display.ensureCursorVisible()

    def play_audio_logic(self, filepath):
        """מנהלת את הניגון והחלפת מצבי הכפתורים"""
        clicked_button = self.sender()

        # א. אם לחצו על כפתור שכבר מנגן - עוצרים הכל
        if clicked_button.text() == " ■ עצור ניגון ":
            self.audio_player_object.stop()
            clicked_button.setText(" ▶ השמע הודעה ")
            self.current_playing_button = None
            return

        # ב. אם יש כפתור אחר שמנגן כרגע - מחזירים אותו למצב רגיל
        if self.current_playing_button is not None:
            try:
                self.current_playing_button.setText(" ▶ השמע הודעה ")
            except:
                pass 

        # ג. עדכון הכפתור הנוכחי למצב "מנגן"
        clicked_button.setText(" ■ עצור ניגון ")
        self.current_playing_button = clicked_button

        # ד. הפעלת הניגון בת'רד נפרד
        # ה-audio_player_object שלך כבר עושה sd.stop() בפנים, אז הוא יקטע את הקודם
        threading.Thread(
            target=self._play_thread_worker, 
            args=(filepath, clicked_button), 
            daemon=True
        ).start()

    def _play_thread_worker(self, filepath, button):
        """מריץ את הקובץ ומחכה לסיום כדי לאפס את ה-UI"""
        # קריאה לפונקציה המקורית שלך
        self.audio_player_object.Play_Audio_By_File(filepath)
        
        # המתנה לסיום הניגון (מבלי לתקוע את ה-GUI)
        import sounddevice as sd
        sd.wait() 
        
        # ה. החזרת הכפתור למצב "נגן" רק אם הוא עדיין הכפתור הפעיל
        if self.current_playing_button == button:
            button.setText(" ▶ השמע הודעה ")
            self.current_playing_button = None

    def crt_group_gui(self, group_name, group_id):
            
            item = QListWidgetItem(group_name)
            item.setData(Qt.ItemDataRole.UserRole, group_id) # שמירת ה-ID בתוך האובייקט
            self.groups_list.addItem(item)

    def add_group_gui(self, gruop_id, user):
            
            print(f"group id is {gruop_id} and im in {self.in_group_gui}")
            if gruop_id != self.in_group_gui:
                print("not in group")
                return
            
            print("in group")
            self.combo_members.addItem(user)

    def remv_group_gui(self, group_id, user):

            if group_id != self.in_group_gui and user != self.username:
                return
            
            if group_id == self.in_group_gui and user != self.username:
                index = self.combo_members.findText(user)

                if index >= 0: # בודק שהטקסט אכן קיים
                    self.combo_members.removeItem(index)
                else:
                    print("error in combobox user removal")
                
            if group_id != self.in_group_gui and user == self.username:

                for i in range(self.groups_list.count() - 1, -1, -1):
                    item = self.groups_list.item(i)
            # שליפת ה-ID ששמרת ב-UserRole
                    item_id = item.data(Qt.ItemDataRole.UserRole)
            
                    if item_id == group_id:
                        # הסרת הפריט מהרשימה
                        removed_item = self.groups_list.takeItem(i)
                        # חשוב: takeItem רק מוציא את הפריט מהתצוגה, צריך למחוק אותו מהזיכרון
                        del removed_item
                        print(f"Item with ID {group_id} removed.")
                        return # עוצר אחרי שמצא והסיר

            if group_id == self.in_group_gui and user == self.username:

                self.no_group_ui_change()
                if self.recorder:
                    try:
                        self.recorder.Force_close()
                    except:
                        pass

                self.reset_audio_state()    
                for i in range(self.groups_list.count() - 1, -1, -1):
                    item = self.groups_list.item(i)
            # שליפת ה-ID ששמרת ב-UserRole
                    item_id = item.data(Qt.ItemDataRole.UserRole)
            
                    if item_id == group_id:
                        # הסרת הפריט מהרשימה
                        removed_item = self.groups_list.takeItem(i)
                        # חשוב: takeItem רק מוציא את הפריט מהתצוגה, צריך למחוק אותו מהזיכרון
                        del removed_item
                        print(f"Item with ID {group_id} removed.")
                        return # עוצר אחרי שמצא והסיר
                    
    def show_Server_says(self, str):
        QMessageBox.information(self, "תשובה", str)

    def closeEvent(self, event):
        if self.recorder:
            try:
                self.recorder.Force_close()
            except:
                pass
        
        # 2. סגירת הקליינט
        if hasattr(self, 'client'):
            self.client.close_client()

        # 3. תיקון שגיאת כתיב: accept ולא accpept
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window1 = LoginWindow()
    window1.show()
    sys.exit(app.exec())