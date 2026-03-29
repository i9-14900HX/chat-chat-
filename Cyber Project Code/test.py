import os 
from datetime import datetime
import tkinter as tk
from tkinter import messagebox


print(datetime.now().strftime("%y%m%d%H%M%S%f"))
print(datetime.now().strftime("%y%m%d%H%M%S%f"))

'''

def send_message():
    msg = entry.get()
    if msg:
        chat_box.insert(tk.END, f"You: {msg}")
        entry.delete(0, tk.END)

root = tk.Tk()
root.title("Chat - Tkinter")

# חלון רשימת משתמשים
users_frame = tk.Frame(root)
users_frame.pack(side=tk.LEFT, fill=tk.Y)
tk.Label(users_frame, text="Users").pack()
users_list = tk.Listbox(users_frame)
users_list.pack(fill=tk.BOTH, expand=True)
for u in ["Alice", "Bob", "Charlie"]:
    users_list.insert(tk.END, u)

# חלון הודעות
chat_frame = tk.Frame(root)
chat_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
chat_box = tk.Text(chat_frame, height=15)
chat_box.pack(fill=tk.BOTH, expand=True)
entry = tk.Entry(chat_frame)
entry.pack(fill=tk.X)
send_btn = tk.Button(chat_frame, text="Send", command=send_message)
send_btn.pack()

root.mainloop()
'''

my_list = [1, 2, 3]
print(my_list)
my_list.append(4)
print(my_list)
my_list.insert(0, 0)
print(my_list)

from PyQt6.QtGui import QGuiApplication
from PyQt6.QtCore import Qt  # <--- ה-Qt נמצא כאן

scheme = QGuiApplication.styleHints().colorScheme()

if scheme == Qt.ColorScheme.Dark:
    print("System is in Dark Mode")
elif scheme == Qt.ColorScheme.Light:
    print("System is in Light Mode")

'''
print (str(scheme))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QPalette
from PyQt6.QtCore import Qt

def get_current_scheme():
    app = QApplication.instance()
    scheme = app.styleHints().colorScheme()
    
    # אם המערכת מחזירה Unknown, נבדוק ידנית לפי בהירות הרקע
    if scheme == Qt.ColorScheme.Unknown:
        bg_color = app.palette().color(QPalette.ColorRole.Window)
        # אם הבהירות (Luminance) נמוכה מ-128, זה כנראה Dark Mode
        if bg_color.lightness() < 128:
            return "Dark"
        else:
            return "Light"
            
    return "Dark" if scheme == Qt.ColorScheme.Dark else "Light"

print(f"Detected Theme: {get_current_scheme()}")
'''

import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QPalette
from PyQt6.QtCore import Qt

def get_current_scheme():
    # מקבל את האובייקט הקיים של האפליקציה
    app = QApplication.instance()
    
    # בדיקה לביטחון: אם האפליקציה עדיין לא קיימת
    if not app:
        return "Unknown"

    scheme = app.styleHints().colorScheme()
    
    if scheme == Qt.ColorScheme.Dark:
        return "Dark"
    elif scheme == Qt.ColorScheme.Light:
        return "Light"
    else:
        # בדיקה ידנית לפי בהירות צבע הרקע (למקרה של Unknown)
        bg = app.palette().color(QPalette.ColorRole.Window)
        return "Dark" if bg.lightness() < 128 else "Light"

# --- כאן הסדר הנכון ---
app = QApplication(sys.argv) # יוצרים את האפליקציה קודם!

print(f"Detected Theme: {get_current_scheme()}")

# כאן יבוא שאר הקוד שלך (חלונות וכו')
# app.exec() 