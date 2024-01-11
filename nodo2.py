#& C:/Python311/python.exe "e:/Uni/IA año 4/Primer Cuatri/SGSSI/ProyectoSGSSI/nodo2.py"
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
MIIEowIBAAKCAQEAu1m+HHB87GzZhUZPK045/VhIu7lfr57H3w9p3jz4PML9+0kW
VtuxD0iEhFPWPUY1GFk4AfIIWggv59aYV10nb6hrS0NR6brq7tNg1Sf39BCLZ5xR
K0jxu8YLAYhiOzISYpS6NzVWGLZBGO+F8Q63FjqbO6Vne0uoAQtz8x3CHIu7/q6U
mmDpseynPG/VQ3avdeqTA4ovSJ+/VVPLscKF4zHVQpKVn9l+mXjywYJrejyq5PFu
Tc9uNsVyTMs29nZEaMkvm9vJIxSGeDxX3FeLs9fwFDcgDCdxDfpTFLopaSQBQLsC
8VDa+IGk4SMaHgbtA1bfI+duQZlBPihcAc3M+QIDAQABAoIBABzaJXuyPB7Z5YbP
jN4tsiMIr0zPr8N3R68bq9FooM8UtXH3L7xJIYOpxpStZ5MwpnkdNlGgYTZiR+Rj
iTr9Etdwf7OLxsfgvBDzFxjEirw4twtKCLsKhQXGqke+ZehZXfj2EBZz/ZIZMT3C
l2VH/5yqAmGFZ8IWZOViSuVAKjZkcA5eo6Ha/9C7u5oFBz9R33o0WabQ6aTp+Mwp
92v4tqUDKYczd8ulYiNjz99hgOaG0lJ0PW018gmISKz+MWQDd5OxsI4BM6O5lMzK
aJl9Tx/DZQWUsuzC1V9jLY+gjp1UyElxEiQmaUgbRo1PrJNrEZYSkTCjjs+w4Pit
tb4b2b0CgYEA5xVxIhFOvBZFQ2ifze5ida3cCv1LF2w4VKU/o/rADtig5qDZZoAP
/3aQgOBqb/7ef8OJ8TvMzmxkX9b6pMPSFzLbnARrAanS9sSQ8LpXDb9PKKq0Jx9c
kaE+Z1rhSzSaE9VR7dfHnH7jsdWISXP4gO9C7+YM+ej9UePzL16LR70CgYEAz40k
XJN3m4BPOE7KTvdabYLKPywyYvBLF3Zv3zLbG9FNxYm42ruXghjbxLwSFZGbal04
Fbqzo2/yG9gwWe7/RZNj7a6kjSL46oRnRQUTZGedGGCFQuo5XVEpS3047+mjqc3e
CYJAzDgZMVHlu5PW6UzytNclLIag7X4yGDRmn+0CgYAeoHrkFwMmbpUzf/ReKNAn
5KkbU8LWEePNZDFxHFTEIvYAWyU1LpfwNdilHBk/SrpWmKX5sQFOApOzGB0UJVf8
9yKgJP3BtK5fQmIrZacQDWECdM13ufJc4tAQhr0BaLFbG5TGPykXlsG62iA8DADN
pehrP0RNAxI//kRG7PLsyQKBgHulhysLw27FUuylq8q9e4bQKzLVXrMommPA8EbV
IkmBOMbdFF5i8ZDUxGCA9nkZBLCqFlaDoq9UarUB51Q8mKFXfGnF6EwYsJfuByPM
MVBYlfNG1T0XEtOwHVzWngv3ccQgXA3oJjhDl2aVdrp4Ccl1SQZJQeEz1z2FN8zJ
svXFAoGBALGv3aMcJe6y1NmDawgB0qzaVMbjGNkGdDPTAWZ8mXHlbnJRM2CYO4Gp
bxuG2mppKqRxGb9qu9ZF/MbAwZWenmdiOP6Lq32G+4T00Bfq0+vZVKaSesPYTgt7
veO5eIAylQaBdZcTzVXNC2pyNVtUIAHFdhHYyZyyX71NonNJAKCx
-----END RSA PRIVATE KEY-----"""

PublicKey = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1m+HHB87GzZhUZPK045
/VhIu7lfr57H3w9p3jz4PML9+0kWVtuxD0iEhFPWPUY1GFk4AfIIWggv59aYV10n
b6hrS0NR6brq7tNg1Sf39BCLZ5xRK0jxu8YLAYhiOzISYpS6NzVWGLZBGO+F8Q63
FjqbO6Vne0uoAQtz8x3CHIu7/q6UmmDpseynPG/VQ3avdeqTA4ovSJ+/VVPLscKF
4zHVQpKVn9l+mXjywYJrejyq5PFuTc9uNsVyTMs29nZEaMkvm9vJIxSGeDxX3FeL
s9fwFDcgDCdxDfpTFLopaSQBQLsC8VDa+IGk4SMaHgbtA1bfI+duQZlBPihcAc3M
+QIDAQAB
-----END PUBLIC KEY-----"""

direccion = hashlib.sha256(PublicKey.encode('utf-8')).hexdigest()

minero = Blockchain(puerto=5001, direccion=direccion)

minero.agregar_nodo("localhost:5000")

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