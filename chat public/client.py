import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox, Menu

# Fonction pour recevoir des messages du serveur
def receive_messages(sock):
    while True:
        try:
            msg = sock.recv(1024).decode()
            if msg:
                chat_window.config(state=tk.NORMAL)
                chat_window.insert(tk.END, f"{msg}")
                chat_window.config(state=tk.DISABLED)
                chat_window.yview(tk.END)
        except:
            print("Error receiving message")
            break

# Fonction pour envoyer des messages au serveur
def send_message(event=None):
    msg = message_entry.get()
    message_entry.delete(0, tk.END)
    if msg.startswith("@"):
        chat_window.config(state=tk.NORMAL)
        chat_window.insert(tk.END, f"You (private): {msg}\n")
        chat_window.config(state=tk.DISABLED)
    else:
        chat_window.config(state=tk.NORMAL)
        chat_window.insert(tk.END, f"You: {msg}\n")
        chat_window.config(state=tk.DISABLED)
    sock.sendall(msg.encode())

# Fonction pour demander les informations d'authentification ou d'inscription
def authenticate_or_register():
    has_account = simpledialog.askstring("Account", "Do you have an account? (yes/no):", parent=root).strip().lower()
    sock.sendall(has_account.encode())

    if has_account == 'yes':
        pseudo = simpledialog.askstring("Pseudo", "Enter your pseudo:", parent=root).strip()
        password = simpledialog.askstring("Password", "Enter your password:", parent=root, show='*').strip()
        sock.sendall(pseudo.encode())
        sock.sendall(password.encode())
    else:
        pseudo = simpledialog.askstring("New Pseudo", "Enter your new pseudo:", parent=root).strip()
        password = simpledialog.askstring("New Password", "Enter your new password:", parent=root, show='*').strip()
        sock.sendall(pseudo.encode())
        sock.sendall(password.encode())

# Fonction pour montrer une boîte de message en cas d'erreur
def show_error_message(message):
    messagebox.showerror("Error", message)

# Fonction pour changer de thème
def change_theme(theme):
    if theme == "Dark":
        root.config(bg='#2b2b2b')
        title_label.config(bg='#2b2b2b', fg='white')
        chat_frame.config(bg='#2b2b2b')
        chat_window.config(bg='#1e1e1e', fg='white')
        message_frame.config(bg='#2b2b2b')
        message_entry.config(bg='#1e1e1e', fg='white')
        send_button.config(bg='#3a3a3a', fg='white')
    elif theme == "Light":
        root.config(bg='#f0f0f0')
        title_label.config(bg='#f0f0f0', fg='black')
        chat_frame.config(bg='#f0f0f0')
        chat_window.config(bg='white', fg='black')
        message_frame.config(bg='#f0f0f0')
        message_entry.config(bg='white', fg='black')
        send_button.config(bg='#dcdcdc', fg='black')

# Configuration de la fenêtre principale
root = tk.Tk()
root.title("My Chat Application")
root.geometry("500x500")

# Menu de thèmes
menu = Menu(root)
root.config(menu=menu)
theme_menu = Menu(menu, tearoff=0)
menu.add_cascade(label="Themes", menu=theme_menu)
theme_menu.add_command(label="Dark", command=lambda: change_theme("Dark"))
theme_menu.add_command(label="Light", command=lambda: change_theme("Light"))

# Titre du chat
title_label = tk.Label(root, text="Welcome to My Chat", font=('Arial', 16), pady=10)
title_label.pack()

chat_frame = tk.Frame(root)
chat_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

chat_window = scrolledtext.ScrolledText(chat_frame, width=50, height=20, font=('Arial', 12), state=tk.DISABLED, wrap=tk.WORD)
chat_window.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

message_frame = tk.Frame(root)
message_frame.pack(padx=10, pady=10, fill=tk.X, side=tk.BOTTOM)

message_entry = tk.Entry(message_frame, width=40, font=('Arial', 12))
message_entry.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=True)
message_entry.bind("<Return>", send_message)

send_button = tk.Button(message_frame, text="Send", command=send_message, font=('Arial', 12), relief=tk.FLAT)
send_button.pack(side=tk.RIGHT, padx=10, pady=10)

# Connexion au serveur
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('192.168.105.22', 5555))

# Authentification ou inscription de l'utilisateur
authenticate_or_register()

# Lancer un thread pour recevoir des messages
receive_thread = threading.Thread(target=receive_messages, args=(sock,))
receive_thread.start()

# Définir le thème initial
change_theme("Dark")

root.mainloop()
