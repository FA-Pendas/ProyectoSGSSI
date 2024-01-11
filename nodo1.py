#& C:/Python311/python.exe "e:/Uni/IA año 4/Primer Cuatri/SGSSI/ProyectoSGSSI/nodo1.py"
from Blockchain import Blockchain
from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import base64
import hashlib
from cryptography.hazmat.primitives import serialization
import time
import threading
from copy import deepcopy
import requests

#Son claves aleatorias, no usar en ningun sitio que no sea de pruebas
PrivateKey = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsk1DNozt+kQJqhJwpDuJ5oOwu24RePnDMswzO5mC9nNDTa/Q
o6qUldbdAZAJTRnfPO5HU4WcjEKDPBDqfSbduUL4KMyJ8o5oFiR/5ypdlvsbdXNu
c/HpBmEkv304x3hLbkcz6pYdhvzWVDFvKavkzciUiMW9cF8ZPmwVK9gFyAwjrz3B
HIltcuG8eijlat4iXh2L/1hr0rPJX29PRkqxVZf67WOihx8nj+tQazFbS+dmxIyg
+P2G286iC8uAVJQ4hvRFPxAjnwzEpiFEYerN5zJ2Pzavsuvqbg2HUy30nPg6Eki8
grpBLMtFPvacINepV7E+reW6lSisKKNAYzqNIQIDAQABAoIBAAXW4UWka0LP/vUH
8j0etLnM7vkkdgQH7KxO4w/89hILh6pqq02WOj7csOjqhl4fuR+YuiidGURqr+ZE
COSdD5PlV+qWJZ/A/t2tclboHJ/jjMGq9x9q+R5ms2UQvSRN50KEUx9IAqLiHZmC
SPQMwiCPL3YklmYGEfXpD5nGUwzQctkpdpEnqp5E9jomYYPb6RL/i1PrBRf5kbw3
wIgvMgygqY9SL5j+04B7BSUT+dum89B7I38AmEmf0/KBKCQHpc2EmaEEvqBd90ok
8qvaBYafkvFVUWqYeaXfi8MsNAUQsyE+lfGzYxrf0N/9LU8wJhuNiODH9OMfjTrn
hpyzy4UCgYEA87SYTT6kat4pPFo64KCrH7g8NMHbHKb2mH64RBpIzbnMIhG6JFas
250IyGl+ArIB896ddc/3WKKGOLQlVd4rB9+I/sVeNDoeiE1aNC3M6kz0mxMQTmZp
8jpOv932LVMU2YzFtGvv0fWeoCb+F9WggBWBi+Y7obeki3s5K/EcHXsCgYEAu0v+
Q5EiYiBcNA4Lt8pOury0+NcIOKspuW5kp91b/fME9OOk2dlTlYsibUcaZ99qV8+s
71kKZmpAJzmy+GzQlIFxLoHXMNJ41RUzbNK/OHzjdYXkSvce+8dNg1jBZZJmZS4J
/JCb0mE/XGZoFMUErGAWSBKCGcUr+31B0r0iBxMCgYEAo01RfPlL3VyOzyU7LMgc
wv2GQmfgNjvfI+JOATyHqmsk0XOFgtIdtG9usjSWPqIfUtXKN2aqvNbzD84O8pIT
zYvJVcbVUDPdv8Htfudt11bH1Z4ZoB9aQPk3SbQnQMnaP8jntfVZ1xw6NeDLBRee
HBXNH/yf2sae2OQyNDK1fz8CgYAp15tRGu5Uf6g5lN23TIH0I85GPTu/9TUYEPp5
qfEwNYdo8iZU6MFMik3Bnf3fMMFAJswamIjDQn9cg/5gk2axlo1jd2xMouiNqfPY
HujLRNNH4QaUXMrWMrs1WbGy8Fbhybw/aUr2X/VYviQIZ89YdwrjRQc9nJfr0hrP
aqNccwKBgECja/RduinmHwm6Y+a8buZYtpd+8BoRnOMQLBwEDbjwBY0Ypb4Tk8sp
fLDpTVLmYaqgCB0H8HqTx44sAZTjg/Qpd16o2b9LWAbJU70JZtIoY9WnlFX7g2Zn
FbqIqvmMaojkud6kjiGm/ysLLkSkDQeCcc5U2Q5D2ZJrDsYIiiQU
-----END RSA PRIVATE KEY-----"""

PublicKey = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsk1DNozt+kQJqhJwpDuJ
5oOwu24RePnDMswzO5mC9nNDTa/Qo6qUldbdAZAJTRnfPO5HU4WcjEKDPBDqfSbd
uUL4KMyJ8o5oFiR/5ypdlvsbdXNuc/HpBmEkv304x3hLbkcz6pYdhvzWVDFvKavk
zciUiMW9cF8ZPmwVK9gFyAwjrz3BHIltcuG8eijlat4iXh2L/1hr0rPJX29PRkqx
VZf67WOihx8nj+tQazFbS+dmxIyg+P2G286iC8uAVJQ4hvRFPxAjnwzEpiFEYerN
5zJ2Pzavsuvqbg2HUy30nPg6Eki8grpBLMtFPvacINepV7E+reW6lSisKKNAYzqN
IQIDAQAB
-----END PUBLIC KEY-----"""

direccion = hashlib.sha256(PublicKey.encode('utf-8')).hexdigest()

minero = Blockchain(puerto=5000, direccion=direccion)

minero.agregar_nodo("localhost:5001")

app = Flask(__name__)

@app.route("/")
def obtener_cadena_de_bloques():
    respuesta = {
        'cadena_de_bloques': minero.cadenaDeBloques
    }
    return jsonify(respuesta), 200

@app.route("/detener_minado", methods=['GET'])
def detener_minado():
    minero.DETENERHILO = True
    minero.hilo.join()

@app.route("/anadir_transaccion", methods=['POST'])
def anadir_transaccion():
    transaccion = request.get_json()
    ok = False
    if minero.validar_transaccion_envio(transaccion):
        ok = minero.anadir_transaccion(transaccion)
    respuesta = {"ok": ok}
    return jsonify(respuesta), 200

@app.route("/anadir_nodo", methods=['POST'])
def anadir_nodo():
    nodo = request.get_json()
    nodo = nodo.get("nodo")
    if nodo:
        ok = minero.agregar_nodo(nodo)
        respuesta = {"ok": ok}
        return jsonify(respuesta), 200
    else:
        respuesta = {"ok": False}
        return jsonify(respuesta), 400

@app.route("/reemplazar_cadena", methods=['POST'])
def reemplazar_cadena():
    cadenaConPropagador = request.get_json()
    respuesta = minero.reemplazar_cadena(cadenaConPropagador)
    return jsonify(respuesta), 200

@app.route("/obtener_transaccion_de_envio" , methods=['GET'])
def obtener_transaccion_de_envio():
    t = request.args.get('t')
    return jsonify(minero.obtener_info_transaccion_envio(t)), 200

@app.route("/obtener_bloque" , methods=['GET'])
def obtener_bloque():
    b = request.args.get('b')
    return jsonify(minero.obtener_info_bloque(b)), 200

@app.route("/obtener_transaccion" , methods=['GET'])
def obtener_transaccion():
    pass #PRIMERO MIRAR QUE HACER EN LA CLASE
    t = request.args.get('t')
    return jsonify(minero.obtener_info_transaccion(t)), 200

app.run(debug=True, port=minero.puerto)