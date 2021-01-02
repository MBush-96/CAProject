# -*- coding: utf-8 -*-
"""
Created on Wed Dec 30 22:27:16 2020
"""

import base64
from kivy.app import App
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from kivy.properties import ObjectProperty
from kivy.uix.screenmanager import Screen,ScreenManager
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.floatlayout import FloatLayout
from kivy.lang import Builder

Centered_InPopupX = .435
Centered_InPopupY = .8
Popup_HeightY = 200
Popup_WidthX = 400
_FileUsed = "PUEIntact.txt"
_OutputFile = "PUEIntact.encrypted"
Password_forcrypt  = "PlaceHolder" #PH figure out how to get this whenever any diffrent person uses it
Password_tocrypt = Password_forcrypt.encode()
salt = b'\xc4\xe4\x18\xb8j\x874\xd5r\xef\xbcV\xf2\xbe\xb0\xaf'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256,
    length=32,
    salt=salt,
    iterations=100100,
    backend=default_backend()
)

key = base64.urlsafe_b64encode(kdf.derive(Password_tocrypt))
try:
    f = open(_FileUsed, "x")
    f.close()
except FileExistsError:
    pass




class CreateAccountWindow(Screen):
    username = ObjectProperty(None)
    password = ObjectProperty(None)
    email = ObjectProperty(None)
    
    def MakeNameErrorPopup(self):
        _floatlayout_NameError = FloatLayout()
        _floatlayout_NameError.add_widget(Label(text="Invalid username no special characters allowed.\nOr username is already taken.",
                                      size_hint=(.1, .1), pos_hint={"x": Centered_InPopupX, "y": Centered_InPopupY}))
        
        _floatlayout_NameError.add_widget(Label(text="#, $, % ,^, &, !, SPACE, Etc..", size_hint=(.1, .1),
                                                pos_hint={"x": Centered_InPopupX, "y": Centered_InPopupY -.3}))
        return _floatlayout_NameError
    
    def MakeAttrErrorPopup(self):
        _floatlayout_AttrError = FloatLayout()
        _floatlayout_AttrError.add_widget(Label(text="Username/Password can't be blank.", size_hint=(.1, .1),
                                                pos_hint={"x": Centered_InPopupX, "y": Centered_InPopupY }))
        return _floatlayout_AttrError
    
    def InvalidEmail(self):
        _floatlayout_InvEmail = FloatLayout()
        _floatlayout_InvEmail.add_widget(Label(text="Email is invalid.", size_hint=(.1, .1),
                                         pos_hint={"x": Centered_InPopupX, "y": Centered_InPopupY }))
        return _floatlayout_InvEmail
    
    def InvalidUsername(self):
        _floatlayout_UsernameTaken = FloatLayout()
        _floatlayout_UsernameTaken.add_widget(Label(text="Username is taken.", size_hint=(.1, .1),
                                                    pos_hint={"x": Centered_InPopupX, "y": Centered_InPopupY}))
        return _floatlayout_UsernameTaken
    
    def SuccessSignUp(self):
            print("Name -> ", self.username.text, "Password -> ", self.password.text, "Email -> ", self.email.text)
            with open(_FileUsed, "a") as f:
                f.write(self.username.text + ";" + self.password.text + ";" + self.email.text + "\n")
            with open(_FileUsed, "rb") as f: # open as reading bytes
                data = f.read() # read bytes of file

            fernet = Fernet(key)
            encrypted = fernet.encrypt(data)

            with open(_OutputFile, "wb") as f:
                f.write(encrypted)
            self.username.text = ""
            self.password.text = ""
            self.email.text = ""
        
    def GoToLoginScreen(self):
        sm.current = "Login"
    
    def Button(self):
        tv_has_specChar = False
        UsernameIsTaken = False
            
        for letter in self.username.text:
            if letter.isalpha() or letter.isdigit():
                tv_has_specChar = False
            else:
                tv_has_specChar = True
                break
            
        with open(_FileUsed, "r") as f:
            for line in f:
                if line.startswith(self.username.text):
                    UsernameIsTaken = True
            
        if tv_has_specChar or UsernameIsTaken:
            Pop_NameError = Popup(title = "Invalid Username.",
                            content=self.MakeNameErrorPopup(),
                            size_hint = (None, None), size = (Popup_WidthX, Popup_HeightY))
            
            
            Pop_NameError.open()
            self.password.text = ""
            
        elif self.username.text == "" or self.password.text == "":
            Pop_AttrError = Popup(title = "You must fill out your username/password.",
                            content=self.MakeAttrErrorPopup(), 
                            size_hint = (None, None), size = (Popup_WidthX, Popup_HeightY))

            Pop_AttrError.open()
            self.password.text = ""
        elif "@" not in self.email.text and ".com" not in self.email.text and self.email.text != "":
            Pop_InvalEmail = Popup(title = "Invalid Email",
                                   content = self.InvalidEmail(),
                                   size_hint = (None, None), size = (Popup_WidthX, Popup_HeightY))
            Pop_InvalEmail.open()
            self.password.text = ""
            self.email.text = ""
        
        else:
            self.SuccessSignUp()
            sm.current = "Login"
        
            
class LoginWindow(Screen):
    uname = ObjectProperty(None)
    passwl = ObjectProperty(None)
    
    def SuccessfulLogin(self):
        sm.current = "SuccessLogin"
        
    def ButtonCA(self):
        sm.current = "CreateAccount"
        
    def ButtonLogin(self):
        with open(_FileUsed, "r") as f:
            for line in f:
                if line.startswith(self.uname.text) and self.uname.text != "":
                    if self.passwl.text in line:
                        self.SuccessfulLogin()
                    else:
                        self.uname.text = ""
                        self.passwl.text = ""
                else:
                    self.uname.text = ""
                    self.passwl.text = ""

class LoggedIn(Screen):
    pass

class WindowManager(ScreenManager):
    pass

kv = Builder.load_file("diffrent.kv")
sm = WindowManager()

Screens = [LoginWindow(name="Login"), CreateAccountWindow(name="CreateAccount"), LoggedIn(name="SuccessLogin")]
for screen in Screens:
    sm.add_widget(screen)

sm.current = "Login"
        
class Diffrent(App):
    def build(self):
        self.title = "Login"
        return sm

    
if __name__ == '__main__':
    Diffrent().run()