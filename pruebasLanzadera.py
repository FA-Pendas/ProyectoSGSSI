import Blockchain
from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, "+ request.args.get('t') +"!</p>"
    #http://localhost:5000/?t=Endika
    #Hello, Endika!

@app.route("/stop")
def parar():
    return "<p>Se Supone que se paro</p>"
    #request.get_json() ASI PILLO EL BODY DE LA REQUEST
    #request.data

@app.route("/obtener_transaccion_de_envio" , methods=['GET'])
def obtener_transaccion_de_envio():
    t = request.args.get('t')
    return Blockchain.obtener_transaccion_de_envio()

app.run(debug=True, port=5000)