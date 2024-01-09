#La b lo vuelve en bytes
# a = 'a'
# a = bytes(a, 'utf-8')
# b = b"a"
# print(a[0]>>6, b[0]>>6)


# from Blockchain import Blockchain

# a = Blockchain()
# a.hola()


# emisor = "emitir"
# receptor = "receptor"
# cantidad = 10
# print(f"{emisor} {receptor} {cantidad}")


# import time
# print(time.time())
# time.sleep(1)
# print(time.time())

######
# semaforo = False

# def bucle():
#     print("Entre al bucle")
#     global semaforo
#     while True:
#         if semaforo:
#             break
#     semaforo = False
#     print("Sali del bucle")

# def cambiar():
#     global semaforo
#     semaforo = True

# from flask import Flask

# app = Flask(__name__)

# @app.route("/")
# def hello_world():
#     bucle()
#     return "<p>Hello, World!</p>"

# @app.route("/stop")
# def parar():
#     cambiar()
#     return "<p>Se Supone que se paro</p>"

import threading
import time

class MiClase:

    def __init__(self):
        self.semaforo = False
        self.hilo = threading.Thread(target=self.bucle)
        self.hilo.start()

    def bucle(self):
        print("Entre al bucle")
        while True:
            if self.semaforo:
                break
        self.semaforo = False
        print("Sali del bucle")

    def cambiar(self):
        self.semaforo = True

a = MiClase()
print("Hola")
time.sleep(1)
a.cambiar()