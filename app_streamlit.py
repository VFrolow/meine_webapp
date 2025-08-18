import streamlit as st
import tkinter
import tkinter as tk
from tkinter import *
import customtkinter as ctk
import CTkListbox as ctklb
from CTkListbox import *
import os
import sqlite3
from tkcalendar import Calendar

version = 1.26

path_database = r'C:/todo_lib'
if not os.path.exists(path_database):
    os.makedirs(path_database)
    fp = open('C:/todo_lib/todo_database.db', 'x')
    fp.close()

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

window = Tk()
window.title("ToDo")
window.resizable(False, False)
window_height= 510
window_width = 500
screen_width = window.winfo_screenwidth()
screen_height = window.winfo_screenheight()
x_cordinate = int((screen_width/2) - (window_width/2))
y_cordinate = int((screen_height/2) - (window_height/2))
window.geometry("{}x{}+{}+{}".format(window_width, window_height, x_cordinate, y_cordinate))
window.configure(background='grey20')



def do_aufgabe_hinzufuegen():

    if e_aufgabe.get() == "":
        e_aufgabe.configure(fg_color='indian red')
    else:
        e_aufgabe.configure(fg_color='grey39')
        win_date = Tk()
        win_date.title("ToDo")
        win_date.resizable(False, False)
        win_date_height = 320
        win_date_width = 300
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x_cordinate = int((screen_width / 2) - (win_date_width / 2))
        y_cordinate = int((screen_height / 2) - (win_date_height / 2))
        win_date.geometry("{}x{}+{}+{}".format(win_date_width, win_date_height, x_cordinate, y_cordinate))
        win_date.configure(background='grey20')

        def do_ok_date():

            # In Datenbank speichern
            _id = 11
            zeiger.execute(""" INSERT INTO task_list VALUES (?,?) """,
                       (e_aufgabe.get(), _id))  # neue Aufgabe in Datenbank speichern
            verbindung.commit()

            aufgaben_liste.insert('end', e_aufgabe.get())
            e_aufgabe.delete(0, "end")
            # verbindung.close()
            win_date.destroy()
            pass


        # Kalender
        cal = Calendar(win_date, selectmode='day', locale='de_DE', disabledforeground='red',
                   cursor="hand2", background=ctk.ThemeManager.theme["CTkFrame"]["fg_color"][1],
                   selectbackground=ctk.ThemeManager.theme["CTkButton"]["fg_color"][1])
        cal.grid(row=1, column=0, padx=10, pady=10)

        l_entry_date = ctk.CTkLabel(win_date, text="Bis wann soll die Aufgabe erledigt werden?", text_color="white")
        l_entry_date.grid(row=0, column=0, padx=10, pady=10)

        b_ok_date = ctk.CTkButton(win_date, command=do_ok_date, text="OK",
                                       corner_radius=20, width=40, height=40,
                                       text_color='white', fg_color='RoyalBlue4', hover_color='DodgerBlue2')
        b_ok_date.grid(row=2, column=0, padx=10, pady=10)

def do_aufgabe_erledigt():
    e_aufgabe.configure(fg_color='grey39')
    if aufgaben_liste.get() == None or aufgaben_liste == 0:
        print("nichts ausgewählt")
    else:
        ausgeweahlt_id = aufgaben_liste.curselection()
        ausgeweahlt_name = aufgaben_liste.get()
        print(ausgeweahlt_id)
        print(ausgeweahlt_name)
        erledigt_liste.insert('end', ausgeweahlt_name)
        _id=22
        zeiger.execute(""" INSERT INTO done_list VALUES (?,?) """, (ausgeweahlt_name, _id))
        aufgaben_liste.delete(ausgeweahlt_id)
        zeiger.execute("DELETE FROM task_list WHERE _task_=?", (ausgeweahlt_name,))
        ausgewählt_name = None
        verbindung.commit()                                                                                                 # db speichern



#Boxen
aufgaben_liste = CTkListbox(window,width=200, height=300)
aufgaben_liste.grid(row=1, column=0, padx=10, pady=10)
erledigt_liste = CTkListbox(window,width=200, height=300)
erledigt_liste.grid(row=1, column=1, padx=10, pady=10)

#Label
l_aufgabe = ctk.CTkLabel(window,text="Aufgaben", text_color="white")

l_aufgabe.grid(row=0, column=0, padx=10, pady=10, sticky='s')
l_erledigt = ctk.CTkLabel(window,text="Erledigt",text_color="white")
l_erledigt.grid(row=0, column=1, padx=10, pady=10, sticky='s')

#Eingabefeld
e_aufgabe = ctk.CTkEntry(window,width=450, height=40, fg_color='grey39')
e_aufgabe.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky='s')

#Button
b_aufgabe_hinzufuegen = ctk.CTkButton(window, command=do_aufgabe_hinzufuegen, text="Aufgabe hinzufügen",
                                      corner_radius=20, width=200, height=40,
                                      text_color='white', fg_color='red4', hover_color='firebrick1')
b_aufgabe_hinzufuegen.grid(row=3, column=0, padx=10, pady=10)
b_aufgabe_erledigt = ctk.CTkButton(window, command=do_aufgabe_erledigt, text="Aufgabe erledigt",
                                    corner_radius=20, width=200, height=40,
                                    text_color='white', fg_color='RoyalBlue4', hover_color='DodgerBlue2')
b_aufgabe_erledigt.grid(row=3, column=1, padx=10, pady=10)






#Datenbank auslesen
verbindung = sqlite3.connect("C:/todo_lib/todo_database.db")                                                            # Verbindung zur Datenbank herstellen
zeiger = verbindung.cursor()

zeiger.execute("create table if not exists task_list (_task_ VARCHAR(64), task_id VARCHAR(16))")                        # Variable(n) in Datenbank erstellen, fals nicht vorhanden
zeiger.execute("create table if not exists done_list (_done_ VARCHAR(64), done_id VARCHAR(16))")                        # Variable(n) in Datenbank erstellen, fals nicht vorhanden

zeiger.execute("SELECT COUNT(*) FROM task_list")                                                                        # Anzahl der Einträge
task_inhalt_index = zeiger.fetchone()

zeiger.execute("SELECT COUNT(*) FROM done_list")
done_inhalt_index = zeiger.fetchone()

zeiger.execute("SELECT * FROM task_list")                                                                               # Inhalt
task_inhalt = zeiger.fetchall()

zeiger.execute("SELECT * FROM done_list")
done_inhalt = zeiger.fetchall()

print (task_inhalt)
print (done_inhalt)

if not task_inhalt_index[0] == 0:                                                                                            # Wenn Liste nicht leer
    for task_innen in task_inhalt:
        print (task_innen[0])
        aufgaben_liste.insert('end',task_innen[0])
    pass

if not done_inhalt_index[0] == 0:                                                                                            # Wenn Liste nicht leer
    for done_innen in done_inhalt:
        print (done_innen[0])
        erledigt_liste.insert('end',done_innen[0])
    pass



window.mainloop()
