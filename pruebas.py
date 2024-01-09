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









#asdsadasdsadad
# import threading
# import time

# class MiClase:

#     def __init__(self):
#         self.semaforo = False
#         self.hilo = threading.Thread(target=self.bucle)
#         self.hilo.start()

#     def bucle(self):
#         print("Entre al bucle")
#         while True:
#             if self.semaforo:
#                 break
#         self.semaforo = False
#         print("Sali del bucle")

#     def cambiar(self):
#         self.semaforo = True

# a = MiClase()
# print("Hola")
# time.sleep(1)
# a.cambiar()

# a = {1: \
#      345, 12: 4356, 46: 345}
# print(len(a))

# import hashlib

# print(type(hashlib.sha256("hola".encode('utf-8')).hexdigest())) #str

# a = {123: 34, 234: 45, 345: 56}

# a.pop(123)
# print(a)
# a.pop(123, None) #Para que no de error
# print(a)

# a = {1: 2, 3: 4, 5: 6}
# print(str(a))

# a[3] = 556

# print(str(a))

# a.pop(3)
# a[3] = 556

# print(str(a))

# import time
# for i in range(100):
#     print(time.time())

a = "0x" + "f"*64

print(a)

a = int(a, 16)>>4

print(a)

a = hex(a)

print(a)

a = int(a, 16)

print(a)