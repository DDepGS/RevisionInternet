from tkinter import *
from tkinter import ttk
import tkinter as tk
import tkinter.font as font
import nmap
import threading
import time
import os
import platform
import pandas as pd

from plyer import notification


window= Tk()
window.geometry('670x800')
window.title('Escaneo')
window.resizable(False, False)

frame = ttk.Frame()
columns=('Dirección', 'Estado')

lista= ttk.Treeview(frame, columns=columns, show='headings', height=30)
#lista.heading('ip', text='Dirección IP')
#lista.heading('state', text='Estado')
lista.tag_configure('up', background='#559258', foreground='white')
lista.tag_configure('down', background='#8a1111', foreground='white')

for col in columns:
    lista.heading(col, text=col, command=lambda: treeview_sort_column(lista, col, False))

lista.column(column='Dirección',anchor=CENTER)
lista.column(column='Estado',anchor=CENTER)


def notify(message, title):
    if platform.system() == 'Darwin':
        #codigo para permitir que se generen en IOS
        os.system("osascript -e 'display notification \"{}\" with title \"{}\"'".format(message, title))
    else:
        notification.notify(
            title=title,
            message=message,
            timeout = 3)

finalizar=True
textlabel=StringVar()

def host():
    global scanbefore1
    textlabel.set('Escaneo de la red en proceso...')
    while finalizar:
        lista.delete(*lista.get_children())
        host='10.12.63.0/24'
        nm = nmap.PortScanner()
        nm.scan(host,'80', '-v --max-rate 100')

        for k in range (len(nm.all_hosts())):
            scanbefore1=[[0]*2 for l in range (len(nm.all_hosts()))]
        i=0

        for host in nm.all_hosts():
            if scanbefore1[i][1]=='up' and nm[host].state=='down':
                state='down'
                while state!='up':
                    time.sleep(20)
                    newscan=nmap.PortScanner()
                    newscan.scan(host,'80', '-v')
                    state=newscan[host].state()
                    if state=='down':
                        a=a+1
                    if a==10:
                        notify('El Host '+host+ ' no tiene internet', 'Alerta')
                        lista.insert('','end',host, tags='down', open= True,text =host, values=(nm[host].state()))
                        a=0
                if a<10:
                    a=0

            scanbefore1[i]=[host,nm[host].state()]
            i=i+1
            if nm[host].state()=='up':
                lista.insert('','end',host, tags='up', open= True, values=(host,nm[host].state()))
            else:
                lista.insert('','end',host, open= True, values=(host,nm[host].state()))

        time.sleep(1800)

t=threading.Thread(target=host)
t.start()


#Hilo de las direcciones enlazadas al servidor 3
def host2():
    global scanbefore2
    
    while finalizar:
        host='187.174.171.0/24'
        nm = nmap.PortScanner()
        nm.scan(host,'80', '-v --max-rate 100')

        for k in range (len(nm.all_hosts())):
            scanbefore2=[[0]*2 for l in range (len(nm.all_hosts()))]

        i=0
        for host in nm.all_hosts():
            if scanbefore2[i][1]=='up' and nm[host].state=='down':
                state='down'
                while state!='up':
                    time.sleep(20)
                    newscan=nmap.PortScanner()
                    newscan.scan(host,'80', '-v')
                    state=newscan[host].state()
                    if state=='down':
                        a=a+1
                    if a==10:
                        notify('El Host '+host+ ' no tiene internet', 'Alerta')
                        lista.insert('','end',host, tags='down', open= True, values=(host, nm[host].state()))
                        a=0
                if a<10:
                    a=0

            scanbefore2[i]=[host,nm[host].state()]
            i=i+1
            if nm[host].state()=='up':
                lista.insert('','end',host, tags='up', open= True, values=(host,nm[host].state()))
            else:
                lista.insert('','end',host, open= True, values=(host, nm[host].state()))

        time.sleep(1800)

t2=threading.Thread(target=host2)
t2.start()

#Hilo de las direcciones enlazadas al servidor 4
def host3():
    global scanbefore3
    
    while finalizar:
        host='201.116.248.0/24'
        nm = nmap.PortScanner()
        nm.scan(host,'80', '-v --max-rate 100')

        for k in range (len(nm.all_hosts())):
            scanbefore3=[[0]*2 for l in range (len(nm.all_hosts()))]

        i=0
        for host in nm.all_hosts():
            if scanbefore3[i][1]=='up' and nm[host].state=='down':
                state='down'
                while state!='up':
                    time.sleep(20)
                    newscan=nmap.PortScanner()
                    newscan.scan(host,'80', '-v')
                    state=newscan[host].state()
                    if state=='down':
                        a=a+1
                    if a==10:
                        notify('El Host '+host+ ' no tiene internet', 'Alerta')
                        lista.insert('','end',host, tags='down', open= True, values=(host, nm[host].state()))
                        a=0
                if a<10:
                    a=0

            scanbefore3[i]=[host,nm[host].state()]
            i=i+1
            if nm[host].state()=='up':
                lista.insert('','end',host, tags='up', open= True, values=(host,nm[host].state()))
            else:
                lista.insert('','end',host, open= True, values=(host,nm[host].state()))

        time.sleep(1800)

t3=threading.Thread(target=host3)
t3.start()

def host4():
    global scanbefore4
    
    while finalizar:
        host='10.21.128.0/24'
        nm = nmap.PortScanner()
        nm.scan(host,'80', '-v --max-rate 100')

        for k in range (len(nm.all_hosts())):
            scanbefore4=[[0]*2 for l in range (len(nm.all_hosts()))]

        i=0
        for host in nm.all_hosts():
            if scanbefore4[i][1]=='up' and nm[host].state=='down':
                state='down'
                while state!='up':
                    time.sleep(20)
                    newscan=nmap.PortScanner()
                    newscan.scan(host,'80', '-v')
                    state=newscan[host].state()
                    if state=='down':
                        a=a+1
                    if a==10:
                        notify('El Host '+host+ ' no tiene internet', 'Alerta')
                        lista.insert('','end',host, tags='down', open= True, values=(host, nm[host].state()))
                        a=0
                if a<10:
                    a=0

            scanbefore4[i]=[host,nm[host].state()]
            i=i+1
            if nm[host].state()=='up':
                lista.insert('','end',host, tags='up',open= True, values=(host,nm[host].state()))
            else:
                lista.insert('','end',host, open= True, values=(host, nm[host].state()))

        time.sleep(1800)

#Hilo de las direcciones enlazadas al servidor cinco
t4=threading.Thread(target=host4)
t4.start()

click=0

def parar():
    global finalizar
    global click
    if click!=1:
        finalizar=False
        textlabel.set('Se ha detenido el escaneo')
        click=1

def reiniciar():
    global click
    global finalizar
    if click!=2:
        finalizar=True
        t=threading.Thread(target=host)
        t.start()
        t2=threading.Thread(target=host2)
        t2.start()
        t3=threading.Thread(target=host3)
        t3.start()
        t4=threading.Thread(target=host4)
        t4.start()
        textlabel.set('Se ha reiniciado el escaneo...')
        click=2


label=Label(window, textvariable=textlabel).grid(pady=5, column=2, sticky='nsew') 
Label(window, text='Si hay una IP sin internet se presentará una notificación de Windows').grid(row=1, column=2, sticky='nsew')


Button(window, text='Detener escaneo', command=parar, bg='#7a1f25', relief='raised', fg='white').grid(row=2, column=0, padx=10, pady=5, sticky='nsew')
Button(window, text='Reiniciar escaneo', command=reiniciar).grid(row=2, column=5, padx=10, pady=5, sticky='nsew')

placeholder = StringVar(window, value='10.21.128.0')
enter=Entry(window, width=40, textvariable=placeholder)
enter.grid(row=3, column=2, pady=10, sticky=tk.W)

def buscar():
    global placeholder
    if not enter.get():
        placeholder='Ingrese IP'
    else:
        lista.selection_set(enter.get())
        lista.focus(enter.get())
        lista.see(enter.get())

def treeview_sort_column(tv, col, reverse):
    l = [(tv.set(k, col), k) for k in tv.get_children('')]
    l.sort(reverse=reverse)

    # rearrange items in sorted positions
    for index, (val, k) in enumerate(l):
        tv.move(k, '', index)

    # reverse sort next time
    tv.heading(col, command=lambda: \
           treeview_sort_column(tv, col, not reverse))

Button(window, text='Buscar', relief='raised', command=buscar).grid(row=3, column=2, sticky=tk.E)

scrollbar=Scrollbar(frame, orient=tk.VERTICAL, command=lista.yview, width=20)
lista.configure(yscroll=scrollbar.set)
lista.grid(column=0, sticky='nsew')
scrollbar.grid(column=10, row=0, sticky='nsew')
frame.grid(column=2, sticky='nsew')
frame.columnconfigure(10, weight=1)
frame.rowconfigure(0, weight=1)

window.mainloop()
t.join()
t2.join()
t3.join()
t4.join() 
finalizar=False