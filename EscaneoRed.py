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


window= Tk() #Genera la ventana
window.geometry('670x800')
window.title('Escaneo')
window.resizable(False, False) #Impide que se modifique las dimensiones de la ventana

frame = ttk.Frame()#Se crea un Frame donde estará la lista de las IP

columns=('Dirección', 'Estado')

lista= ttk.Treeview(frame, columns=columns, show='headings', height=30)#Se genera la lista
lista.tag_configure('up', background='#559258', foreground='white') #Etiquetas que cambian el color de la fila 
lista.tag_configure('down', background='#8a1111', foreground='white')

for col in columns: #Genera los encabezados con comando para ordenar
    lista.heading(col, text=col, command=lambda: treeview_sort_column(lista, col, False))

lista.column(column='Dirección',anchor=CENTER) #Columnas con nombre y posición de los datos
lista.column(column='Estado',anchor=CENTER)

#Función para generar notificaciones en el SO
def notify(message, title):
    if platform.system() == 'Darwin':
        #Código para permitir que se generen en IOS
        os.system("osascript -e 'display notification \"{}\" with title \"{}\"'".format(message, title))
    else:
        notification.notify(
            title=title,
            message=message,
            timeout = 3)

finalizar=True #Variable para el ciclo indefinido
textlabel=StringVar() #Variable para el texto de una etiqueta 

#Hilo de las direcciones 10.12.63.0/24
def host():
    global scanbefore1
    textlabel.set('Escaneo de la red en proceso...')
    while finalizar: #Ciclo infinito para escanear toda la red 
        lista.delete(*lista.get_children()) #Elimina los datos de la lista para evitar duplas
        host='10.12.63.0/24'#Rango de IP 
        nm = nmap.PortScanner() #Nuevo objeto tipo PortScanner de NMAP
        nm.scan(host,'80', '-v --max-rate 100') #Escaneo de la red para el puerto TCP 80 con un máximo de 100 paquetes cada segundo

        for k in range (len(nm.all_hosts())): #Ciclo para llenar con 0 una matriz para las IP y sus estados
            scanbefore1=[[0]*2 for l in range (len(nm.all_hosts()))]
        
        i=0 #Contador

        for host in nm.all_hosts(): #Ciclo para todos las IP para saber si dejaron de tener internet
            if scanbefore1[i][1]=='up' and nm[host].state=='down': #Condicional para saber si estado anterior pasa de up a down con el estado actual
                state='down' #Entonces se considera que el estado es down
                while state!='up': #Ciclo que se realiza solo si el estado es down
                    time.sleep(20) #se realiza cada 20 segundos
                    newscan=nmap.PortScanner()
                    newscan.scan(host,'80', '-v') #Otro escaneo únicamente del host en down
                    state=newscan[host].state()
                    if state=='down': #Si el estado es down se incrementa un contador
                        a=a+1
                    if a==10: #Si el contador es igual a 10 se envía la notificación
                        notify('El Host '+host+ ' no tiene internet', 'Alerta')
                        lista.insert('','end',host, tags='down', open= True,text =host, values=(nm[host].state())) #Se almacena la fila con los datos con su configuración
                        a=0 #Se reinicia el contador
                if a<10:
                    a=0

            scanbefore1[i]=[host,nm[host].state()]#Se almacena el ip y estado en la matriz
            i=i+1 #Incrementa el contador para desplazarse por la matriz

            if nm[host].state()=='up':
                lista.insert('','end',host, tags='up', open= True, values=(host,nm[host].state())) #Se agrega fila con su configuración para up 
            else:
                lista.insert('','end',host, open= True, values=(host,nm[host].state())) #Se agrega fila sin configuración si siempre ha sido down

        time.sleep(1800)#El ciclo espera 30 minutos antes de reiniciar

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

click=0 #Bandera para saber cual boton ha sido presionado

def parar():
    global finalizar
    global click
    if click!=1: #Si es diferente a 1 se iguala finalizar a False, se cambia el texto de la variable para la etiqueta y click a 1
        finalizar=False
        textlabel.set('Se ha detenido el escaneo')
        click=1

def reiniciar():
    global click
    global finalizar
    if click!=2: #Si es diferente a 2 finalizar es True, se cambia el texto de la etiqueta, se llaman a los hilos y click a 2
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


label=Label(window, textvariable=textlabel).grid(pady=5, column=2, sticky='nsew') #Etiqueta principal
Label(window, text='Si hay una IP sin internet se presentará una notificación de Windows').grid(row=1, column=2, sticky='nsew')#Etiqueta secundaria


Button(window, text='Detener escaneo', command=parar, bg='#7a1f25', relief='raised', fg='white').grid(row=2, column=0, padx=10, pady=5, sticky='nsew') #Botón para parar escaneo
Button(window, text='Reiniciar escaneo', command=reiniciar).grid(row=2, column=5, padx=10, pady=5, sticky='nsew')#Botón para reiniciar escaneo

placeholder = StringVar(window, value='10.21.128.0') #Placeholder para la entrada de texto
enter=Entry(window, width=40, textvariable=placeholder)#Entrada de texto para IP a buscar
enter.grid(row=3, column=2, pady=10, sticky=tk.W)

#Función para buscar la IP ingresada
def buscar():
    global placeholder
    if enter.get(): 
        lista.selection_set(enter.get()) #Se selecciona, enfoca y muestra la IP cuyo id es igual 
        lista.focus(enter.get())
        lista.see(enter.get())
    else:
        placeholder.set('Ingrese IP')
        

#Función para ordenar la columna de estado
def treeview_sort_column(tv, col, reverse):
    l = [(tv.set(k, col), k) for k in tv.get_children('')]
    l.sort(reverse=reverse)

    # rearrange items in sorted positions
    for index, (val, k) in enumerate(l):
        tv.move(k, '', index)

    # reverse sort next time
    tv.heading(col, command=lambda: \
           treeview_sort_column(tv, col, not reverse))

Button(window, text='Buscar', relief='raised', command=buscar).grid(row=3, column=2, sticky=tk.E)#Botón para buscar la IP

scrollbar=Scrollbar(frame, orient=tk.VERTICAL, command=lista.yview, width=20)#Scrollbar de la lista
lista.configure(yscroll=scrollbar.set)#Conexión de la lista con el scrollbar
lista.grid(column=0, sticky='nsew')
scrollbar.grid(column=10, row=0, sticky='nsew')
frame.grid(column=2, sticky='nsew')
frame.columnconfigure(10, weight=1)
frame.rowconfigure(0, weight=1)

window.mainloop() #Final de la ventana y de los hilos
t.join()
t2.join()
t3.join()
t4.join() 
finalizar=False