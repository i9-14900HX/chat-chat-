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