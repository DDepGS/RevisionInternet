'''Daniela Gutiérrez Sandoval
Programa para notificar si un dispositivo
pierde la conexión a internet para la CSI SSP
Octubre 2023'''

import nmap
import threading
import time
import os
import platform
import pandas as pd

from plyer import notification

#función para generear notificaciones 
def notify(message, title):
    if platform.system() == 'Darwin':
        #codigo para permitir que se generen en IOS
        os.system("osascript -e 'display notification \"{}\" with title \"{}\"'".format(message, title))
    else:
        notification.notify(
            title=title,
            message=message,
            timeout = 3)

#Hilo del primer servidor
def server1():
    global scanbefores1
    scanbefores1=[0,0]
    global a

    #ciclo para hacerlo indefinidamente
    while True:
        host='10.12.63.206'
        nm = nmap.PortScanner() 
        nm.scan(host,'80', '-v --max-rate 100') #Escaneo de la dirección y del puerto 80
        
        #Comparación de un arreglo entre el estado anterior almacenado del escaneo y el nuevo
        if scanbefores1[1]=='up' and nm[host].state()=='down':
            state='down'
            #Si el estado pasa de up a down, inicia ciclo para reiterar que está down
            while state!='up':
                time.sleep(20) #Tiempo de espera de 20 segundos
                newscan=nmap.PortScanner()
                newscan.scan(host,'80', '-v')
                state=newscan[host].state()
                if state=='down':
                    a=a+1 #contador para las veces en que el host se presenta caido
                #Si el contador es igual a 10 se manda una notificación al os y se resetea el contador
                if a==10:
                    notify('El Host '+host+ ' no tiene internet', 'Alerta')
                    a=0
            if a>=1:
                a=0

        scanbefores1=[host, nm[host].state()] #almacena el host y el estado de éste en un arreglo para la comparación

        time.sleep(1800) #tiempo de espera de 30 minutos

s1=threading.Thread(target=server1) #declaración de inicio del hilo del primer servidor 
s1.start()

#Hilo del segundo servidor
def server2():
    global scanbefores2
    scanbefores2=[0,0]
    while True:
        host='10.12.63.207'
        nm = nmap.PortScanner()
        nm.scan(host,'80', '-v --max-rate 100')
       
        if scanbefores2[1]=='up' and nm[host].state()=='down':
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
                    a=0
            if a>=1:
                a=0

        scanbefores2=[host, nm[host].state()]

        time.sleep(1800)

s2=threading.Thread(target=server2)
s2.start()

#Hilo del tercer servidor
def server3():
    global scanbefores3
    scanbefores3=[0,0]
    while True:
        host='187.174.171.97'
        nm = nmap.PortScanner()
        nm.scan(host,'80', '-v --max-rate 100')

        if scanbefores3[1]=='up' and nm[host].state()=='down':
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
                    a=0
            if a>=1:
                a=0

        scanbefores3=[host, nm[host].state()]

        time.sleep(1800)

s3=threading.Thread(target=server3)
s3.start()

#Hilo del cuarto servidor
def server4():
    global scanbefores4
    scanbefores4=[0,0]
    while True:
        host='201.116.248.194'
        nm = nmap.PortScanner()
        nm.scan(host,'80, 11443', '-v --max-rate 100')

        if scanbefores4[1]=='up' and nm[host].state()=='down':
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
                    a=0
            if a>=1:
                a=0

        scanbefores4=[host, nm[host].state()]

        time.sleep(1800)

s4=threading.Thread(target=server4)
s4.start()

#Hilo del quinto servidor
def server5():
    global scanbefores5
    scanbefores5=[0,0]
    while True:
        host='10.21.128.201'
        nm = nmap.PortScanner()
        nm.scan(host,'80', '-v --max-rate 100')

        if scanbefores5[1]=='up' and nm[host].state()=='down':
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
                    a=0
            if a>=1:
                a=0

        scanbefores5=[host, nm[host].state()]

        time.sleep(1800)

s5=threading.Thread(target=server5)
s5.start()

#Hilo de las direcciones enlazadas al primer y segundo servidor
def host():
    global scanbefore1
    
    while True:
        host='10.12.63.0/25'
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
                        a=0
                if a>=1:
                    a=0

            scanbefore1[i]=[host,nm[host].state()]
            i=i+1

        time.sleep(1800)

t=threading.Thread(target=host)
t.start()

#Hilo de las direcciones enlazadas al servidor 3
def host2():
    global scanbefore2
    
    while True:
        host='187.174.171.0/25'
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
                        a=0
                if a>=1:
                    a=0

            scanbefore2[i]=[host,nm[host].state()]
            i=i+1

        time.sleep(1800)

t2=threading.Thread(target=host2)
t2.start()

#Hilo de las direcciones enlazadas al servidor 4
def host3():
    global scanbefore3
    
    while True:
        host='201.116.248.0/25'
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
                        a=0
                if a>=1:
                    a=0

            scanbefore3[i]=[host,nm[host].state()]
            i=i+1

        time.sleep(1800)

t3=threading.Thread(target=host3)
t3.start()

def host4():
    global scanbefore4
    
    while True:
        host='10.21.128.0/25'
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
                        a=0
                if a>=1:
                    a=0

            scanbefore4[i]=[host,nm[host].state()]
            i=i+1

        time.sleep(1800)

#Hilo de las direcciones enlazadas al servidor cinco
t4=threading.Thread(target=host4)
t4.start()