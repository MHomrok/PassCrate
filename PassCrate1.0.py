import sqlite3
import base64
import bcrypt
import tkinter as tk
import tkinter.ttk as ttk
import os
from tkinter import messagebox as msg
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


basedir = os.path.dirname(__file__)

#Custom button for removing entries - icon
class MyButton(tk.Button):
    def __init__(self, *args, **kwargs):
        tk.Button.__init__(self, *args, **kwargs)
        self.photo = tk.PhotoImage(file=os.path.join(basedir, "icontrash.png"))
        self["image"] = self.photo
        self.config(background="white", borderwidth=0, width=25, height=25)

class Pencil(tk.Button):
    def __init__(self, *args, **kwargs):
        tk.Button.__init__(self, *args, **kwargs)
        self.photo = tk.PhotoImage(file=os.path.join(basedir, "iconpencil.png"))
        self["image"] = self.photo
        self.config(background="white", borderwidth=0, width=25, height=25)

class Addbutton(tk.Button):
    def __init__(self, *args, **kwargs):
        tk.Button.__init__(self, *args, **kwargs)
        self.photo = tk.PhotoImage(file=os.path.join(basedir, "iconadd.png"))
        self["image"] = self.photo
        self.config(background="white", borderwidth=0, width=35, height=35)


def main():
    global cursor
    global sql_connect

    #Load database
    sql_connect = sqlite3.connect("database.db")
    cursor = sql_connect.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='master'")
    if not cursor.fetchone():
        cursor.execute("CREATE TABLE master (username TEXT, password TEXT)")

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='passwords'")
    if not cursor.fetchone():
        cursor.execute("CREATE TABLE passwords (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, username TEXT, password TEXT)")

    check_master = cursor.execute("SELECT username FROM master").fetchall()

    #Check if master password exists
    if check_master:
        show_login_screen()
    else:
        show_register_screen()


#Show saved passwords from the database
def load_list():
    s = ttk.Style()
    s.configure('lg.TSeparator', background='#b3d3f2')
    global e
    global m
    cursor.execute("SELECT * FROM passwords ORDER BY LOWER(title)")
    h = 35
    i=1
    j=0
    for data in cursor: 
        for j in range(len(data)-1):
            e = tk.Entry(list_frame, width=30, font=("Segoe UI", 11), borderwidth=5, relief=tk.FLAT) 
            e.grid(row=i, column=j)
            if j > 0:
                e.insert(tk.END, f.decrypt(data[j+1]))
            else:
                e.insert(tk.END, data[j+1])
            e.bind("<Button-3>", popup)
            m = tk.Menu(list_frame, tearoff = 0)
            m.add_command(label = "Copy", command = lambda: copy_text(False))
        canvas.configure(height="%d" % (h))
        h = h + 35
        b = MyButton(list_frame, command = lambda d=str(data[0]):del_item(d))       #Add trash button to the end
        b.grid(row=i, column=5)
        pen = Pencil(list_frame, command = lambda x=data[1], y=f.decrypt(data[2]), z=f.decrypt(data[3]), id=str(data[0]):edit_scr(x, y, z, id))
        pen.grid(row=i, column=4)
        sep = ttk.Separator(list_frame, orient="horizontal", style="lg.TSeparator") #Add line after row
        sep.grid(column=0, row=i+1, sticky="we", columnspan=6, padx=15)     
        i=i+2
    updateScrollRegion()


#Copy selected text
def copy_text(event):
    try:
        selected = e.selection_get()
        root.clipboard_clear()
        root.clipboard_append(selected)
    except tk.TclError:
        pass


#Popup for copy function
def popup(event):
    try:
        m.tk_popup(event.x_root, event.y_root)
    finally:
        m.grab_release()


#Delete item from the database
def del_item(id):  
    warning = msg.askyesnocancel("Delete Entry.", "Are you sure? ", icon='question')
    if warning:
        cursor.execute("DELETE FROM passwords WHERE id=(?)", (id, ))
        sql_connect.commit()
        for w in list_frame.grid_slaves(): # remove all rows first 
            w.grid_forget() # remove row
        load_list()
        updateScrollRegion()
        add_button.lift()


def updateScrollRegion():
	root.update_idletasks()
	canvas.config(scrollregion=canvas.bbox("all"))


def show_main_screen():
    global root
    global add_button
    global list_frame
    global canvas
    global m

    root = tk.Tk()
    root.iconbitmap(default=os.path.join(basedir, "keyicon.ico"))
    root.title("PassCrate 1.0")
    root.resizable(False, False)

    w = 835 # width for the Tk root
    h = 500 # height for the Tk root
    ws = root.winfo_screenwidth() # width of the screen
    hs = root.winfo_screenheight() # height of the screen
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)
    root.geometry('%dx%d+%d+%d' % (w, h, x, y))

    root.wm_attributes("-transparentcolor", "red")

    packer = tk.Frame(root,bg="white")
    packer.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)
    packer1 = tk.Frame(root,bg="white")
    packer1.pack(side=tk.RIGHT, fill=tk.BOTH)

    header = tk.Frame(packer)
    l=tk.Label(header, width=31, text="Title", borderwidth=0, anchor="w", bg="white", fg="#44719c", font=("Segoe UI", 11))
    l.grid(row=0, column=0)
    l=tk.Label(header, width=31, text="Username", borderwidth=0, anchor="w", bg="white", fg="#44719c", font=("Segoe UI", 11))
    l.grid(row=0, column=1)
    l=tk.Label(header, width=31, text="Password", borderwidth=0, anchor="w", bg="white", fg="#44719c", font=("Segoe UI", 11))
    l.grid(row=0, column=2)
    header.pack(anchor=tk.NW, padx=15)
    
    canvas = tk.Canvas(packer, height=35)
    canvas.pack(fill=tk.X, side=tk.LEFT, expand=1, anchor=tk.NW)

    sb = ttk.Scrollbar(packer1, orient=tk.VERTICAL, command=canvas.yview)
    sb.pack(fill=tk.Y, side=tk.RIGHT)

    list_frame = tk.Frame(canvas)
    list_frame.config(bg="white")
    list_frame.pack(fill=tk.X)

    canvas.configure(yscrollcommand=sb.set, highlightthickness=0, bg="white")
    canvas.bind("<Configure>", lambda e: canvas.configure(scrollregion = canvas.bbox("all")))
    canvas.create_window(0, 0, window=list_frame, anchor=tk.NW)
    canvas.bind_all("<MouseWheel>", lambda event: canvas.yview_scroll(int(-1*(event.delta/120)), "units"))

    load_list()

    add_button = Addbutton(text="Add", command = add_item_scr)
    add_button.place(x=710, y=440)
    add_button.lift()

    root.mainloop()


def add_item_scr():
    global additem_screen
    global t_add
    global u_add
    global p_add
    global menu

    #Position of root window
    x = root.winfo_rootx()
    y = root.winfo_rooty()

    additem_screen = tk.Toplevel(root)
    additem_screen.iconbitmap(default=os.path.join(basedir, "keyicon.ico"))
    additem_screen.geometry("300x250+%d+%d" % (x+270, y+110))   #Position of add window related to main window
    additem_screen.title("Add Password")
    additem_screen.resizable(False, False)
    frame = tk.Frame(additem_screen)
    frame.pack(pady=10)

    t = ttk.Label(frame, text="Title", font=("Segoe UI", 12), padding=3)
    t.pack()
    t_add = ttk.Entry(frame, font=("Segoe UI", 14))
    t_add.pack()
    t_add.focus()

    u = ttk.Label(frame, text="Username", font=("Segoe UI", 12), padding=3)
    u.pack()
    u_add = ttk.Entry(frame, font=("Segoe UI", 14))
    u_add.pack()

    p = ttk.Label(frame, text="Password", font=("Segoe UI", 12), padding=3)
    p.pack()
    p_add = ttk.Entry(frame, font=("Segoe UI", 14))
    p_add.pack()

    save_button = ttk.Button(frame, text="Save", command = save_item)
    save_button.pack(pady=10)

    additem_screen.bind('<Return>', lambda event: save_item())  #Enter key bind

    #Paste popup menu
    menu = tk.Menu(additem_screen, tearoff = 0)
    menu.add_command(label ="Paste", command = lambda: paste_text(False))  

    #Bindings for paste popups and commands 
    t_add.bind("<Button-3>", lambda event: t_add.focus_set(), add="+") 
    t_add.bind("<Button-3>", paste_popup, add="+") 
    u_add.bind("<Button-3>", lambda event: u_add.focus_set(), add="+")
    u_add.bind("<Button-3>", paste_popup, add="+")
    p_add.bind("<Button-3>", lambda event: p_add.focus_set(), add="+")
    p_add.bind("<Button-3>", paste_popup, add="+")


#Paste function
def paste_text(event):
    try:
        focused_widget = additem_screen.focus_get()
        focused_widget.insert(0, root.clipboard_get())
    except tk.TclError:
        pass
    

#Popup for paste command
def paste_popup(event):
    try:
        menu.tk_popup(event.x_root, event.y_root)
    finally:
        menu.grab_release()


def save_item():
    title_info = t_add.get().encode()
    username_info = f.encrypt(u_add.get().encode())
    password_info = f.encrypt(p_add.get().encode())

    cursor.execute("INSERT INTO passwords (title, username, password) VALUES (?, ?, ?)", (title_info, username_info, password_info))
    sql_connect.commit()

    additem_screen.destroy()
    load_list()
    add_button.lift()


def show_register_screen():
    global register_screen
    global p_reg
    global cp_reg

    register_screen = tk.Tk()
    register_screen.iconbitmap(default=os.path.join(basedir, "keyicon.ico"))
    register_screen.title("PassCrate")
    register_screen.resizable(False, False)
    frame = ttk.Frame(register_screen)
    frame.pack(pady=16)

    w = 300 # width for the Tk
    h = 200 # height for the Tk

    ws = register_screen.winfo_screenwidth() # width of the screen
    hs = register_screen.winfo_screenheight() # height of the screen

    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)

    register_screen.geometry('%dx%d+%d+%d' % (w, h, x, y))

    p = ttk.Label(frame, text="Create Master Password", font=("Segoe UI", 10))
    p.pack(pady=3)
    p_reg = ttk.Entry(frame, font=("Segoe UI", 14))
    p_reg.pack(pady=3)
    p_reg.focus()

    cp = ttk.Label(frame, text="Confirm Master Password", font=("Segoe UI", 10))
    cp.pack(pady=3)
    cp_reg = ttk.Entry(frame, font=("Segoe UI", 14))
    cp_reg.pack(pady=3)

    register_button = ttk.Button(frame, text="Create", command = register)
    register_button.pack(pady=5)

    register_screen.bind('<Return>', lambda event: register())  #Enter key bind
    register_screen.mainloop()


def show_login_screen():
    global basedir
    global login_screen
    global p_log

    login_screen = tk.Tk()
    login_screen.iconbitmap(default=os.path.join(basedir, "keyicon.ico"))
    login_screen.title("PassCrate")
    login_screen.resizable(False, False)
    
    w = 300 # width for the Tk
    h = 150 # height for the Tk

    ws = login_screen.winfo_screenwidth() # width of the screen
    hs = login_screen.winfo_screenheight() # height of the screen

    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)

    login_screen.geometry('%dx%d+%d+%d' % (w, h, x, y))

    frame = ttk.Frame(login_screen)
    frame.pack(pady=13)

    p = ttk.Label(frame, text="Enter Master Password", font=("Segoe UI", 10))
    p.pack(pady=7)
    p_log = ttk.Entry(frame, font=("Segoe UI", 14))
    p_log.pack(pady=1)
    p_log.focus()

    login_button = ttk.Button(frame, text="Login", command = login)
    login_button.pack(pady=15)

    login_screen.bind('<Return>', lambda event: login())    #Enter key bind
    login_screen.mainloop()


def register():
    global f

    reg_password = p_reg.get()
    reg_confpass = cp_reg.get()

    #Check password provided
    if reg_password == reg_confpass:
        reg_password = bcrypt.hashpw(reg_password.encode(), bcrypt.gensalt())
        cursor.execute("INSERT INTO master (username, password) VALUES (?, ?)", ("admin", reg_password))
        sql_connect.commit()    #Input password to database

        #Create fernet on register, from the master password, so user can start using the program right away
        password = p_reg.get().encode()
        salt = "\xa9\x84\x1e\xf3:\x94[\xb7\x9c=\xfebI\x03\xabhO\x13\xb8\x83".encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)

        register_screen.destroy()
        show_main_screen()

    
def login():
    global f

    log_password = p_log.get()
    
    check_password = cursor.execute("SELECT password FROM master").fetchall()
    for x in check_password[0]:
        passvalue = x

    #Create fernet on login, from the master password
    if bcrypt.checkpw(log_password.encode(), passvalue):    #Check password agains database
        password = p_log.get().encode()
        salt = "\xa9\x84\x1e\xf3:\x94[\xb7\x9c=\xfebI\x03\xabhO\x13\xb8\x83".encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        
        login_screen.destroy()
        show_main_screen()


def edit_scr(title, username, password, id):
    global edit_screen
    global t_edit
    global u_edit
    global p_edit
    global menu

    #Position of root window
    x = root.winfo_rootx()
    y = root.winfo_rooty()

    edit_screen = tk.Toplevel(root)
    edit_screen.iconbitmap(default=os.path.join(basedir, "keyicon.ico"))
    edit_screen.geometry("300x250+%d+%d" % (x+270, y+110))   #Position of add window related to main window
    edit_screen.title("Edit Password")
    edit_screen.resizable(False, False)
    frame = tk.Frame(edit_screen)
    frame.pack(pady=10)

    t = ttk.Label(frame, text="Title", font=("Segoe UI", 12), padding=3)
    t.pack()

    t_edit = ttk.Entry(frame, font=("Segoe UI", 14))
    t_edit.insert(0, title)
    t_edit.pack()
    t_edit.focus()

    u = ttk.Label(frame, text="Username", font=("Segoe UI", 12), padding=3)
    u.pack()

    u_edit = ttk.Entry(frame, font=("Segoe UI", 14))
    u_edit.insert(0, username)
    u_edit.pack()

    p = ttk.Label(frame, text="Password", font=("Segoe UI", 12), padding=3)
    p.pack()

    p_edit = ttk.Entry(frame, font=("Segoe UI", 14))
    p_edit.insert(0, password)
    p_edit.pack()

    save_button = ttk.Button(frame, text="Save", command = lambda: save_edit(id))
    save_button.pack(pady=10)

    edit_screen.bind('<Return>', lambda event: save_edit(id))  #Enter key bind

    #Paste popup menu
    menu = tk.Menu(edit_screen, tearoff = 0)
    menu.add_command(label ="Paste", command = lambda: paste_text(False))  

    #Bindings for paste popups and commands 
    t_edit.bind("<Button-3>", lambda event: t_edit.focus_set(), add="+") 
    t_edit.bind("<Button-3>", paste_popup, add="+") 
    u_edit.bind("<Button-3>", lambda event: u_edit.focus_set(), add="+")
    u_edit.bind("<Button-3>", paste_popup, add="+")
    p_edit.bind("<Button-3>", lambda event: p_edit.focus_set(), add="+")
    p_edit.bind("<Button-3>", paste_popup, add="+")


def save_edit(id):
    title_edit = t_edit.get().encode()
    username_edit = f.encrypt(u_edit.get().encode())
    password_edit = f.encrypt(p_edit.get().encode())

    cursor.execute("UPDATE passwords SET title = ?, username = ?, password = ? WHERE id = ?", (title_edit, username_edit, password_edit, id))
    sql_connect.commit()

    edit_screen.destroy()
    load_list()
    add_button.lift()

    
if __name__ == "__main__":
    main()