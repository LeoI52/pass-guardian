"""
@author : Léo IMBERT
@created : 15/04/2025
@updated : 29/05/2025
"""

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import customtkinter as ctk
from PIL import Image
import pyperclip
import hashlib
import string
import random
import base64
import json
import os


class Password(ctk.CTkFrame):

    def __init__(self, master, name:str, password:str, description:str, index:int, passwords_list:list, fill):
        super().__init__(master, 500, 100, border_color="#3282b8", border_width=2)

        self.bin_icon = ctk.CTkImage(dark_image=Image.open("./assets/bin_icon.png"), size=(30, 30))
        self.copy_icon = ctk.CTkImage(dark_image=Image.open("./assets/copy_icon.png"), size=(30, 30))
        self.label_name = ctk.CTkLabel(self, text=name, font=ctk.CTkFont(size=20, underline=True, weight="bold"))
        self.label_password = ctk.CTkLabel(self, text=password, font=ctk.CTkFont(size=18))
        self.label_description = ctk.CTkLabel(self, text=description, font=ctk.CTkFont(slant="italic"))
        self.label_name.place(x=5, y=7)
        self.label_password.place(x=5, y=35)
        self.label_description.place(x=5, y=63)

        self.index = index
        self.passwords_list = passwords_list
        self.fill = fill
        self.delete_toplevel_open = False

        ctk.CTkButton(self, 50, 40, text="", image=self.bin_icon, fg_color="#F71B3c", hover_color="#D11733", command=self.delete).place(x=490, y=52, anchor="ne")
        ctk.CTkButton(self, 50, 40, text="", image=self.copy_icon, command=self.copy).place(x=490, y=48, anchor="se")

    def copy(self):
        pyperclip.copy(self.label_password.cget("text"))

    def delete(self):
        if not self.delete_toplevel_open:
            self.delete_toplevel = ctk.CTkToplevel()
            self.delete_toplevel.title("Delete Password")
            self.delete_toplevel.geometry("500x240+450+200")
            self.delete_toplevel.resizable(False, False)
            self.delete_toplevel.attributes("-topmost", True)
            self.delete_toplevel.protocol("WM_DELETE_WINDOW", self.close_delete_toplevel)
            self.after(250, lambda:self.delete_toplevel.iconbitmap("./assets/icon.ico"))

            self.delete_toplevel_open = True

            ctk.CTkLabel(self.delete_toplevel, text="Delete Password", font=ctk.CTkFont(size=40, underline=True)).place(relx=0.5, y=10, anchor="n")
            ctk.CTkLabel(self.delete_toplevel, text="Please enter the password to delete it", font=ctk.CTkFont(size=18)).place(relx=0.5, y=100, anchor="n")

            delete_entry = ctk.CTkEntry(self.delete_toplevel, 200, font=ctk.CTkFont(size=18), placeholder_text="Password...")
            delete_entry.place(relx=0.5, y=140, anchor="n")
            delete_entry.bind("<Return>", lambda _: self.confirm_delete(delete_entry.get()))

            ctk.CTkButton(self.delete_toplevel, text="Cancel", font=ctk.CTkFont(size=20), command=self.close_delete_toplevel).place(relx=0.2, rely=0.95, anchor="sw")
            ctk.CTkButton(self.delete_toplevel, text="Confirm", font=ctk.CTkFont(size=20), command=lambda:self.confirm_delete(delete_entry.get())).place(relx=0.8, rely=0.95, anchor="se")

    def confirm_delete(self, password:str):
        if password == self.label_password.cget("text"):
            del self.passwords_list[self.index]
            self.fill()
            self.close_delete_toplevel()

    def close_delete_toplevel(self):
        self.delete_toplevel_open = False
        self.delete_toplevel.destroy()

class App(ctk.CTk):

    def __init__(self):

        #? Window Configuration
        super().__init__(fg_color="#0d1b2a")
        self.geometry("800x450+350+150")
        self.title("PassGuardian")
        self.resizable(False, False)
        self.iconbitmap("./assets/icon.ico")
        self.protocol("WM_DELETE_WINDOW", self.close)
        ctk.set_default_color_theme("./assets/theme.json")

        #? Variables
        self.add_toplevel_open = False
        self.data = {}
        self.showing_passwords = []
        self.fernet = None

        #? Images
        self.right_arrow_icon = ctk.CTkImage(dark_image=Image.open("./assets/right_arrow_icon.png"), size=(30, 30))
        self.eye_icon = ctk.CTkImage(dark_image=Image.open("./assets/eye_icon.png"), size=(30, 30))
        self.add_icon = ctk.CTkImage(dark_image=Image.open("./assets/add_icon.png"), size=(30, 30))
        self.search_icon = ctk.CTkImage(dark_image=Image.open("./assets/search_icon.png"), size=(30, 30))
        self.generate_icon = ctk.CTkImage(dark_image=Image.open("./assets/generate_icon.png"), size=(20, 20))

        #? Profile Creation Widgets
        self.profile_creation_label = ctk.CTkLabel(self, text="Profile Creation", font=ctk.CTkFont(size=40, underline=True))
        self.profile_creation_entry = ctk.CTkEntry(self, 400, font=ctk.CTkFont(size=30), placeholder_text="Choose your password...", show="*")
        self.profile_creation_button = ctk.CTkButton(self, 60, 45, text="", image=self.right_arrow_icon, command=self.create_profile)
        self.profile_creation_button_show = ctk.CTkButton(self, 60, 45, text="", image=self.eye_icon, command=self.profile_creation_show)

        #? Login Widgets
        self.login_label = ctk.CTkLabel(self, text="Login", font=ctk.CTkFont(size=40, underline=True))
        self.login_entry = ctk.CTkEntry(self, 400, font=ctk.CTkFont(size=30), placeholder_text="Enter your password...", show="*")
        self.login_button = ctk.CTkButton(self, 60, 45, text="", image=self.right_arrow_icon, command=self.login)
        self.login_button_show = ctk.CTkButton(self, 60, 45, text="", image=self.eye_icon, command=self.login_show)

        #? Menu Widgets
        self.button_add = ctk.CTkButton(self, 60, 45, text="", image=self.add_icon, command=self.add_password)
        self.entry_search = ctk.CTkEntry(self, 200, font=ctk.CTkFont(size=30), placeholder_text="Search...")
        self.label_search = ctk.CTkLabel(self, text="", image=self.search_icon, fg_color="#1b263b")
        self.scrollable_frame_passwords = ctk.CTkScrollableFrame(self, 740, 350)

        #? Start
        if os.path.isfile("./save/save.json"):
            f = open("./save/save.json", "r")
            self.data = json.load(f)
            f.close()
            self.passwords = self.data["passwords"]
            self.place_login()
        else:
            self.place_profile_creation()

        #? Binding
        def unfocus(event):
            if type(event.widget) != str:
                event.widget.focus_set()

        self.bind_all("<Button-1>", unfocus)

        self.profile_creation_entry.bind("<Return>", lambda _: self.create_profile())
        self.login_entry.bind("<Return>", lambda _: self.login())
        self.entry_search.bind("<KeyRelease>", lambda _: self.fill_scrollable_frame())

        #? MainLoop
        self.mainloop()

    def hash(self, password:str)-> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def get_fernet(self, password:str)-> Fernet:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"\xfa\x95\x9c\x88\xd7\xab\x11\x8a\x01z\xf1\xba\xef\xae\xd0\xde", iterations=100_000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def close(self):
        f = open("./save/save.json", "w")
        json.dump(self.data, f, indent=2)
        f.close()
        self.destroy()

    def cap_entry(self, widget, lenght:int):
        if len(widget.get()) > lenght:
            widget.delete(lenght, "end")

    def create_profile(self):
        password = self.profile_creation_entry.get()
        if password:
            self.fernet = self.get_fernet(password)
            f = open("./save/save.json", "x")
            self.data = {"password":self.hash(password), "passwords":[]}
            json.dump(self.data, f, indent=2)
            f.close()
            self.forget_profile_creation()
            self.place_menu()

    def profile_creation_show(self):
        if self.profile_creation_entry.cget("show"):
            self.profile_creation_entry.configure(show="")
        else:
            self.profile_creation_entry.configure(show="*")

    def login(self):
        password = self.login_entry.get()
        if self.hash(password) == self.data["password"]:
            self.fernet = self.get_fernet(password)
            self.forget_login()
            self.place_menu()
            self.fill_scrollable_frame()

    def login_show(self):
        if self.login_entry.cget("show"):
            self.login_entry.configure(show="")
        else:
            self.login_entry.configure(show="*")

    def generate_password(self, widget):
        password = ""
        for _ in range(6):
            password += random.choice(string.ascii_letters)
        for _ in range(2):
            password += random.choice(string.digits)
        password += random.choice(["#","@","&","%","$","€","£"])

        widget.delete("0", "end")
        widget.insert("0", password)

    def add_password(self):
        if not self.add_toplevel_open:
            self.add_toplevel = ctk.CTkToplevel(self)
            self.add_toplevel.title("Add Password")
            self.add_toplevel.geometry("500x280+450+200")
            self.add_toplevel.resizable(False, False)
            self.add_toplevel.attributes("-topmost", True)
            self.add_toplevel.protocol("WM_DELETE_WINDOW", self.close_add_toplevel)
            self.after(250, lambda:self.add_toplevel.iconbitmap("./assets/icon.ico"))

            self.add_toplevel_open = True

            ctk.CTkLabel(self.add_toplevel, text="Add Password", font=ctk.CTkFont(size=30, underline=True)).place(relx=0.5, y=10, anchor="n")

            name_entry = ctk.CTkEntry(self.add_toplevel, 250, font=ctk.CTkFont(size=15), placeholder_text="Name...")
            password_entry = ctk.CTkEntry(self.add_toplevel, 250, font=ctk.CTkFont(size=15), placeholder_text="Password...")
            description_entry = ctk.CTkEntry(self.add_toplevel, 250, font=ctk.CTkFont(size=15), placeholder_text="Description... (Optional)")
            name_entry.place(relx=0.5, y=75, anchor="n")
            password_entry.place(relx=0.5, y=125, anchor="n")
            description_entry.place(relx=0.5, y=175, anchor="n")
            name_entry.bind("<Return>", lambda _: self.confirm_add_toplevel(name_entry.get(), password_entry.get(), description_entry.get()))
            password_entry.bind("<Return>", lambda _: self.confirm_add_toplevel(name_entry.get(), password_entry.get(), description_entry.get()))
            description_entry.bind("<Return>", lambda _: self.confirm_add_toplevel(name_entry.get(), password_entry.get(), description_entry.get()))
            name_entry.bind("<KeyRelease>", lambda _: self.cap_entry(name_entry, 20))
            password_entry.bind("<KeyRelease>", lambda _: self.cap_entry(password_entry, 20))
            description_entry.bind("<KeyRelease>", lambda _: self.cap_entry(description_entry, 50))

            ctk.CTkButton(self.add_toplevel, 30, 30, text="", image=self.generate_icon, command=lambda: self.generate_password(password_entry)).place(x=380, y=125)
            ctk.CTkButton(self.add_toplevel, text="Cancel", font=ctk.CTkFont(size=20), command=self.close_add_toplevel).place(relx=0.2, rely=0.95, anchor="sw")
            ctk.CTkButton(self.add_toplevel, text="Confirm", font=ctk.CTkFont(size=20), command=lambda: self.confirm_add_toplevel(name_entry.get(), password_entry.get(), description_entry.get())).place(relx=0.8, rely=0.95, anchor="se")

    def close_add_toplevel(self):
        self.add_toplevel_open = False
        self.add_toplevel.destroy()

    def confirm_add_toplevel(self, name:str, password:str, description:str):
        if name and password:
            encrypted_password = self.fernet.encrypt(password.encode()).decode()
            self.data["passwords"].append([name, encrypted_password, description])
            self.close_add_toplevel()
            self.fill_scrollable_frame()

    def fill_scrollable_frame(self):
        search = self.entry_search.get()
        self.showing_passwords = [x for x in self.data["passwords"] if search.lower() in x[0].lower()]
        for children in self.scrollable_frame_passwords.winfo_children():
            children.destroy()
        for name, encrypted_password, description in self.showing_passwords:
            try:
                password = self.fernet.decrypt(encrypted_password.encode()).decode()
            except Exception:
                password = "[Decryption failed]"
            index = self.data["passwords"].index([name, encrypted_password, description])
            Password(self.scrollable_frame_passwords, name, password, description, index, self.data["passwords"], self.fill_scrollable_frame).pack(pady=5)

    def forget_profile_creation(self):
        self.profile_creation_label.place_forget()
        self.profile_creation_entry.place_forget()
        self.profile_creation_button.place_forget()
        self.profile_creation_button_show.place_forget()

    def forget_login(self):
        self.login_label.place_forget()
        self.login_entry.place_forget()
        self.login_button.place_forget()
        self.login_button_show.place_forget()

    def place_profile_creation(self):
        self.profile_creation_label.place(relx=0.5, rely=0.35, anchor="s")
        self.profile_creation_entry.place(relx=0.5, rely=0.45, anchor="n")
        self.profile_creation_button.place(relx=0.76, rely=0.45, anchor="nw")
        self.profile_creation_button_show.place(relx=0.24, rely=0.45, anchor="ne")

    def place_login(self):
        self.login_label.place(relx=0.5, rely=0.35, anchor="s")
        self.login_entry.place(relx=0.5, rely=0.45, anchor="n")
        self.login_button.place(relx=0.76, rely=0.45, anchor="nw")
        self.login_button_show.place(relx=0.24, rely=0.45, anchor="ne")

    def place_menu(self):
        self.button_add.place(x=10, y=10, anchor="nw")
        self.entry_search.place(x=790, y=10, anchor="ne")
        self.label_search.place(x=780, y=15, anchor="ne")
        self.scrollable_frame_passwords.place(relx=0.5, y=70, anchor="n")

if __name__ == "__main__":
    App()