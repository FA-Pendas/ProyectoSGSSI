from Blockchain import Blockchain
from flask import Flask, request, jsonify

minero = Blockchain(puerto=5000, direccion="0x123")

app = Flask(__name__)

@app.route("/")
def obtener_cadena_de_bloques():
    respuesta = {
        'cadena_de_bloques': minero.cadenaDeBloques
    }
    return jsonify(respuesta), 200

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
    return minero.obtener_info_transaccion_envio(t), 200

@app.route("/obtener_bloque" , methods=['GET'])
def obtener_bloque():
    b = request.args.get('b')
    return minero.obtener_info_bloque(b), 200

@app.route("/obtener_transaccion" , methods=['GET'])
def obtener_transaccion():
    pass #PRIMERO MIRAR QUE HACER EN LA CLASE
    t = request.args.get('t')
    return minero.obtener_info_transaccion(t), 200



app.run(debug=True, port=5000)