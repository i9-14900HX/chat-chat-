import re
import sys
import threading

from PyQt6.QtWidgets import QApplication, QListWidget, QSizePolicy, QWidget, QPushButton, QLineEdit, QTextEdit, QLabel, QVBoxLayout, QMessageBox, QTableWidget, QMainWindow, QHBoxLayout, QComboBox
from PyQt6.QtCore import QThread, QTime, QTimer, pyqtSignal
from PyQt6.QtGui import QTextCursor, QIcon, QPixmap

from clienttest import Client
from recorder_pyqt_gui import Recorder
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
                self.client.Start_Client() 
                
                # פתיחת חלון הצ'אט והעברת הקליינט אליו
                self.chat_win = ChatWindow(self.client)
                self.chat_win.show()
                
                self.close()
                # כאן תוכל לפתוח את החלון הבא של האפליקציה!
                # self.open_main_app() 
        else:
            QMessageBox.critical(self, "שגיאה", message)
class RetriveGroupInfo():
    pass
class ChatWindow(QWidget):
    def __init__(self, client):
        super().__init__()
        self.client = client
        self.username = self.client.username

        self.recorder = None

        self.audio_state = "idle" # מצבים: idle (רגיל), recording (מקליט), recorded (סיים להקליט)

        self.record_timer = QTimer()
        self.record_timer.timeout.connect(self.update_timer_display)
        self.elapsed_time = QTime(0, 0, 0)

        self.in_group_gui = 0 

        self.init_ui()
        
        self.client.new_serversays_signal.connect(self.show_Server_says)

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
        self.btn_remove = QPushButton("הוצא")
        
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
        #self.client.in_group =  # עדכון הקבוצה הנוכחית בקליינט
        # --- self.in_group_gui =
        group_name = item.text()
        self.lbl_group_name.setText(group_name)
        # --- self.combo_members.clear()
        # --- self.combo_members.addItems(self.client.Get_Group_Members(group_name)) # פונקציה שתחזיר את רשימת החברים בקבוצה מהקליינט
        self.chat_display.clear()
        # כאן תוכל לבקש מהקליינט לשלוף את ההיסטוריה של הקבוצה מה-DB
        # ולשנות את self.client.in_group ל-ID של הקבוצה שנבחרה

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