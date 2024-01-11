# importar librerias
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
import base64
import time
import threading
from copy import deepcopy
import requests

class Blockchain():
    #0x00000fff...ff
    def __init__(self, puerto = 5000, direccion = "0000000000000000000000000000000000000000000000000000000000000000", recompensaInicial = 100, cadaCuantoReducir = 10, dificultadInicial = "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") -> None:#VERSION1.2
        
        self.DETENERHILO = False # Solo usar para acabar con el hilo

        self.seguir = True # Para parar el minado actual
        self.puerto = puerto # Puerto del nodo
        
        self.recompensaInicial = recompensaInicial # Recompensa inicial de cada bloque
        self.cadaCuantoReducir = cadaCuantoReducir # Cada cuanto se reduce la recompensa a la mitad
        self.dificultadInicial = dificultadInicial # Dificultad inicial 

        self.direccion = direccion # Direccion del nodo

        self.bloques = {} # Diccionario de bloques {hash:bloque}
        self.cadenaDeBloques = [] # Lista de hashes de bloques

        self.trasaccionesDeEnvio = {} # Diccionario de transacciones de envio #VERSION1.1

        #SI EN TRANSACCIONES ESTAN YA TODAS LAS TRANSACCIONES, transaccionesNoQuemadas PUEDE SER SOLO UNA LISTA
        self.trasacciones = {} # Diccionario de transacciones existentes {hash:transaccion}
        self.trasaccionesNoQuemadas = {} # Diccionario de transacciones no quemadas {hash:transaccion}
        
        self.mempool = [] # Lista de listas de transacciones de envio pendientes

        self.nodos = set() # Conjunto de nodos conectados

        print("Creamos y minamos el bloque genesis.")
        minado = self.minar(self.bloqueGenesis()) # Minar el bloque genesis
        if minado:
            print("Bloque genesis minado.")
            hash = self.obtener_hash_de_bloque(minado)
            self.bloques[hash] = minado
            self.cadenaDeBloques.append(hash)
    
        self.modificando = False

        self.hilo = threading.Thread(target=self.autoMinado)#Esto lanza un hilo que se encarga de minar todo el rato
        self.hilo.start()

    def autoMinado(self):
        print("Iniciamos el minado automatico.")
        while not self.DETENERHILO:
            #CREAR UNAS VARIABLES POR SI SE ESTA MODIFICANDO LA CADENA PARA NO MINAR
            if not self.modificando:
                print("ESTE ES EL ESTADO DE LA CADENA DE BLOQUES.", self.bloques)
                bloqueAMinar = self.crear_bloque()
                print("Intentamos minar el Bloque: " + str(bloqueAMinar))
                bloque = self.minar(bloqueAMinar)
                if bloque:
                    hash = self.obtener_hash_de_bloque(bloque)
                    print("Hemos logrado minar el Bloque: " + hash)
                    self.bloques[hash] = bloque
                    self.cadenaDeBloques.append(hash)
                    print("Hemos almacenado el bloque y su identificador en la cadena de bloques.")
                    for i in bloque["transacciones"]:
                        if i in self.mempool:
                            self.mempool.remove(i)
                        for j in self.trasaccionesDeEnvio[i]:
                            if j == "transaccionesQuemadas":#Quitamos todas las transacciones quemadas de transaccionesNoQuemadas
                                print("Procedemos a eliminar todas las transacciones quemadas de las transaccionesNoQuemadas.", self.trasaccionesDeEnvio[i][j])
                                for k in self.trasaccionesDeEnvio[i][j]:
                                    if k in self.trasaccionesNoQuemadas:
                                        self.trasaccionesNoQuemadas.pop(k)
                            else:#Añadimos todas las transacciones realizadas en el bloque a las transacciones no quemadas
                                print("Añadimos a las transacciones no quemadas la transaccion", j, self.trasaccionesDeEnvio[i][j])
                                if (not self.trasaccionesDeEnvio[i][j] in self.trasaccionesNoQuemadas[j]) and self.trasaccionesDeEnvio[i][j] in self.trasacciones:
                                    self.trasaccionesNoQuemadas[j] = self.trasacciones[self.trasaccionesDeEnvio[i][j]]
                    print("Hemos eliminado las transacciones del bloque de la mempool.")
                    self.propagar_cadena()
                    print("Hemos propagado la cadena de bloques a todos los nodos conocidos.")
                else:
                    print("No hemos logrado minar el Bloque.")
                    self.seguir = True
            else:
                print("La cadena esta siendo modificada, no minamos.")
                time.sleep(0.01)#Para no sorbecargar el procesador
        print("SE A PARADO EL MINADO AUTOMATICO.")

    def bloqueGenesis(self):
        #El bloque genesis no tiene transacciones
        dificultad = self.dificultadInicial #0x00000fff...ff
        indice = 0
        hash_anterior = "0000000000000000000000000000000000000000000000000000000000000000"
        timeStamp = int(time.time())

        print("Creamos la transaccion de recompensa del bloque genesis y la almacenamos.")
        tc = self.crear_una_transaccion_comision(timeStamp,hash_anterior,self.recompensaInicial)#Coloco el hash anterior porque es todo 0s
        tc["receptor"] = self.direccion
        hashTC = self.obtener_hash_de_transaccion(tc)
        self.trasacciones[hashTC] = tc
        # self.trasaccionesNoQuemadas[hashTC] = tc

        tcEnvio = {"coinbase":hashTC}
        hashTCE = self.obtener_hash_de_transaccion(tcEnvio)
        self.trasaccionesDeEnvio[hashTCE] = tcEnvio
        
        transacciones = [hashTCE] 
        print("Hemos creado el bloque genesis.", {"indice": indice, "transacciones": transacciones, "dificultad": dificultad, "hash-anterior": hash_anterior})
        return {
            "indice": indice,
            "transacciones": transacciones,
            "dificultad": dificultad,
            "hash-anterior": hash_anterior
        }
    
    def validar_bloque_genesis(self, bloque):#VERSION1.2
        print("Validamos si es un bloque genesis.", bloque)
        return bloque["indice"] == 0 and \
                bloque["dificultad"] == self.dificultadInicial and \
                bloque["hash-anterior"] == "0000000000000000000000000000000000000000000000000000000000000000" and \
                "time-stamp" in bloque and \
                "nonce" in bloque and \
                len(bloque) == 6 and \
                "transacciones" in bloque and \
                self.comprobar_prueba_de_trabajo(self.obtener_hash_de_bloque(bloque), bloque["dificultad"]) and \
                self.trasacciones[self.trasaccionesDeEnvio[bloque["transacciones"][0]]["coinbase"]]["cantidad"] == self.recompensaInicial

    def crear_direccion(self, public_key:str) -> str:#VERSION1.2
        print("creamos la direccion a partir de la clave publica.", public_key)
        return self.hash(public_key)

    def crear_mensaje(self, emisor:str, receptor:str, cantidad:int) -> str:#VERSION1.2
        print("Creamos un mensaje a partir del emisor, receptor y cantidad.", f"{emisor} {receptor} {cantidad}")
        return f"{emisor} {receptor} {cantidad}"

    def firmar(self, private_key:str, mensaje:str, contrasena:str = None) -> str:#VERSION1.2
        print("Firmamos el mensaje con la clave privada.", mensaje)
        private_key_from_str = serialization.load_pem_private_key(
            private_key.encode('utf-8'),
            password=contrasena,
            backend=default_backend()
        )
        signature = private_key_from_str.sign(
            mensaje.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Devolvemos la firma en base64.", base64.b64encode(signature).decode('utf-8'))
        return base64.b64encode(signature).decode('utf-8')

    def crear_transaccion(self, public_key:str, private_key:str, emisor:str, receptor:str, cantidad:float, comision:float, transaccionesAQuemar:list[str], contrasena:str = None):#VERSION1.2
        print("Creamos una transaccion de envio apartir de estas a quemar: ", transaccionesAQuemar)
        c = 0
        transaccionesQuemadas = []
        for i in transaccionesAQuemar:
            if self.validar_transaccion_no_quemada(i, emisor):
                c += self.trasaccionesNoQuemadas[i]["cantidad"]
                transaccionesQuemadas.append(i)

        #Hay que crear las 3 o 2 o 1 transaccion
        timeStamp = int(time.time()) #AQUI SE CREA EL TIMESTAMP

        if c < cantidad:
            return False
        elif c == cantidad:
            #Crear solo 1 transaccion
            mensaje = self.crear_mensaje(emisor, receptor, cantidad)
            transaccion = self.crear_una_transaccion(public_key, private_key, mensaje, timeStamp, contrasena)
            print("Creamos la transaccion de envio.", {"enviado":transaccion, #"sobras":None, "comision":None}
                    "transaccionesQuemadas":transaccionesQuemadas})
            return {"enviado":transaccion, #"sobras":None, "comision":None}
                    "transaccionesQuemadas":transaccionesQuemadas}

        elif c == (cantidad + comision):
            #Crear 2 transacciones
            mensajeE = self.crear_mensaje(emisor, receptor, cantidad)
            transaccionE = self.crear_una_transaccion(public_key, private_key, mensajeE, timeStamp, contrasena)

            transaccionC = self.crear_una_transaccion_comision(timeStamp, emisor, comision)
            
            print("Creamos la transaccion de envio.", {"enviado":transaccionE, 
                    "comision":transaccionC,#"sobras":None}
                    "transaccionesQuemadas":transaccionesQuemadas})
            return {"enviado":transaccionE, 
                    "comision":transaccionC,#"sobras":None}
                    "transaccionesQuemadas":transaccionesQuemadas}
            
        elif c > cantidad and comision == 0:
            #Crear 2 transacciones
            mensajeE = self.crear_mensaje(emisor, receptor, cantidad)
            transaccionE = self.crear_una_transaccion(public_key, private_key, mensajeE, timeStamp, contrasena)

            mensajeS = self.crear_mensaje(emisor, emisor, c-cantidad)
            transaccionS = self.crear_una_transaccion(public_key, private_key, mensajeS, timeStamp, contrasena)
            print("Creamos la transaccion de envio.", {"enviado":transaccionE, 
                    "sobras":transaccionS,#"comision":None}
                    "transaccionesQuemadas":transaccionesQuemadas})
            return {"enviado":transaccionE, 
                    "sobras":transaccionS,#"comision":None}
                    "transaccionesQuemadas":transaccionesQuemadas}
            
        else:
            #Crear 3 transacciones
            mensajeE = self.crear_mensaje(emisor, receptor, cantidad)
            transaccionE = self.crear_una_transaccion(public_key, private_key, mensajeE, timeStamp, contrasena)
        
            transaccionC = self.crear_una_transaccion_comision(timeStamp, emisor, comision)

            mensajeS = self.crear_mensaje(emisor, emisor, c-(cantidad+comision))
            transaccionS = self.crear_una_transaccion(public_key, private_key, mensajeS, timeStamp, contrasena)
            print("Creamos la transaccion de envio.", {"enviado":transaccionE, 
                    "sobras":transaccionS,
                    "comision":transaccionC,
                    "transaccionesQuemadas":transaccionesQuemadas})
            return {"enviado":transaccionE, 
                    "sobras":transaccionS,
                    "comision":transaccionC,
                    "transaccionesQuemadas":transaccionesQuemadas}

    def crear_una_transaccion_comision(self, timeStamp, emisor, cantidad):#VERSION1.2
        print("Creamos una transaccion de comision o coinbase.", {
            "time-stamp": timeStamp,
            "emisor": emisor,
            "cantidad": cantidad,
        })
        return {
            "time-stamp": timeStamp,
            "emisor": emisor,
            "cantidad": cantidad,
        }

    def crear_una_transaccion(self, public_key:str, private_key:str, mensaje:str, timeStamp:float,contrasena:str = None):#VERSION1.2
        
        #Obtenemos el receptor, emisor y cantidad del mensaje
        emisor, receptor, cantidad = mensaje.split(" ")

        #Firmamos el mensaje
        firma = self.firmar(private_key, mensaje, contrasena)

        #Devolvemos la transaccion
        print("Creamos una transaccion.", {
            "time-stamp": timeStamp, # O int(time.time())
            "emisor": emisor,
            "receptor": receptor,
            "cantidad": float(cantidad),
            "firma": firma,
            "clave-publica": public_key # Dejar la clave publica en str
        })
        return { #TIENE QUE TENER ESTE ORDEN
            "time-stamp": timeStamp, # O int(time.time())
            "emisor": emisor,
            "receptor": receptor,
            "cantidad": float(cantidad),
            "firma": firma,
            "clave-publica": public_key # Dejar la clave publica en str
        }

    def validar_transaccion_no_quemada(self, transaccion:str, emisor:str) -> bool:#VERSION1.2
        print("Validamos si una transaccion no esta quemada.", f"{transaccion} {emisor}")
        return transaccion in self.trasaccionesNoQuemadas and self.trasaccionesNoQuemadas[transaccion]["receptor"] == emisor
    
    def validar_transaccion_envio(self, transaccion, esHash = False, coinbase=100):#VERSION1.2

        #Siempre las voy a tener almacenadas?
        print("Procedemos a validar una transaccion de envio.", transaccion, coinbase)
        if esHash:
            transaccion = self.trasaccionesDeEnvio[transaccion]
            print("como es el hash obtenemos la informacion de la transaccion de envio.", transaccion)

        if "coinbase" in transaccion and len(transaccion) == 1:#Si la transaccion es la de coinbase
            print("La transaccion es de coinbase, vamos a validarla.")
            esHash = False
            if type(transaccion["coinbase"]) is str:
                esHash = True
            return self.validar_transaccion(transaccion["coinbase"], esHash=esHash, esCoinbase=True, coinbase=coinbase)


        print("Vamos a comprobar que la transaccion de envio es valida.")
        #Tiene que tener al menos una transaccion y las transacciones quemadas
        valido = (len(transaccion) >= 2 and "enviado" in transaccion) and "transaccionesQuemadas" in transaccion

        #Todos los campos de la transaccion tienen que ser validos
        for i in transaccion:
            if i not in ["enviado","sobras","comision", "transaccionesQuemadas"]:
                valido = False
                break
            else:
                if i == "enviado":
                    esHash = False
                    if type(transaccion[i]) is str:
                        esHash = True
                    if not self.validar_transaccion(transaccion[i], esHash=esHash):
                        valido = False
                        break
                elif i == "sobras":
                    esHash = False
                    if type(transaccion[i]) is str:
                        esHash = True
                    if not self.validar_transaccion(transaccion[i], esHash=esHash):
                        valido = False
                        break
                elif i == "comision":
                    esHash = False
                    if type(transaccion[i]) is str:
                        esHash = True
                    if not self.validar_transaccion(transaccion[i], esHash=esHash, esComision=True):
                        valido = False
                        break
                elif i == "transaccionesQuemadas":
                    for j in transaccion[i]:
                        if not self.validar_transaccion_no_quemada(j, transaccion["enviado"]["emisor"]):
                            valido = False
                            break
        if valido:
            print("La transaccion de envio es valida.")
        else:
            print("La transaccion de envio no es valida.")
        return valido

    def anadir_transaccion(self, transaccion: dict) -> str:#VERSION1.2
        print("Nos piden añadir una transaccion a la mempool.", transaccion)
        #Da igual que tengamos la info
        transaccionAux = deepcopy(transaccion)
        if self.validar_transaccion_envio(transaccion):
            print("La transaccion es valida, vamos a añadirla.")
            for i in transaccion:
                if not i == "transaccionesQuemadas":
                    if i == "comision":
                        transaccion[i]["receptor"] = self.direccion
                    h = self.obtener_hash_de_transaccion(transaccion[i])
                    self.trasacciones[h] = transaccion[i]
                    # self.trasaccionesNoQuemadas[h] = transaccion[i]
                    transaccionAux[i] = h

            h = self.obtener_hash_de_transaccion(transaccionAux)
            self.trasaccionesDeEnvio[h] = transaccionAux

            if h not in self.mempool:
                print("la añadimos a la mempool.")
                self.mempool.append(h)#Propagar la transaccion a los demas nodos
                self.seguir = False # Para volver a empezar a minar pero usando la nueva transaccion
                self.propagar_transaccion(transaccion)
                return h
            else:
                print("La transaccion ya esta en la mempool.")
                return False#Delvolver False para que si ya la tenemos no la propaguemos a los nodos que conocemos?
        print("La transaccion no es valida.")
        return False

    def obtener_hash_de_transaccion(self, transaccion):#VERSION1.2
        #Sirve para los dos tipos de transaccion, la individual y la de envio
        print("Obtenemos el hash de una transaccion.", transaccion)
        return self.hash(str(transaccion))

    def recompensa_bloque(self, id):#VERSION1.2
        print("Calculamos la recompensa del bloque.", id, "Que es:",self.recompensaInicial / (2 ** (id // self.cadaCuantoReducir)))
        return self.recompensaInicial / (2 ** (id // self.cadaCuantoReducir))

    def crear_bloque(self):#VERSION1.2
        print("Creamos un bloque con las transacciones que hay en la mempool y la de coinbase.")
        indice = self.ultimo_bloque()["indice"] + 1

        tc = self.crear_una_transaccion_comision(int(time.time()), "0000000000000000000000000000000000000000000000000000000000000000" \
                                                 ,self.recompensa_bloque(indice))
        tc["receptor"] = self.direccion
        hashTC = self.obtener_hash_de_transaccion(tc)
        self.trasacciones[hashTC] = tc
        # self.trasaccionesNoQuemadas[hashTC] = tc

        tcEnvio = {"coinbase":hashTC}
        hashTCE = self.obtener_hash_de_transaccion(tcEnvio)
        self.trasaccionesDeEnvio[hashTCE] = tcEnvio
        
        transacciones = [hashTCE] + self.mempool# En la mempool solo hay transacciones validas

        print("Estas son las transacciones que vamos a añadir al bloque.", transacciones)
        print("Este es el bloque creado", {
            "indice": indice,
            "transacciones": transacciones, 
            "dificultad": self.calcular_dificultad(),
            "hash-anterior": self.hash_ultimo_bloque()
        })

        return {# Se envia el bloque con la informacion necesaria para que el minero lo mine
            "indice": indice,
            "transacciones": transacciones, 
            "dificultad": self.calcular_dificultad(),
            "hash-anterior": self.hash_ultimo_bloque()
            #TIENE QUE SER EN ESTE ORDEN
            # "time-stamp": 1357425863,
            # "nonce": 0,
        }

    def ultimo_bloque(self):#VERSION1.2
        print("El ultimo bloque es el:", self.bloques[self.cadenaDeBloques[-1]])
        return self.bloques[self.cadenaDeBloques[-1]]

    def hash_ultimo_bloque(self):#VERSION1.2
        print("El hash del ultimo bloque es el:", self.cadenaDeBloques[-1])
        return self.cadenaDeBloques[-1]
    
    def minar(self, bloque):#VERSION1.2
        """
        Aqui se le pide que mine 1 bloque
        """
        print("Vamos a minar el bloque:", bloque)
        bloqueMinado = False
        dificultad = bloque["dificultad"]
        bloqueAux = deepcopy(bloque)
        nonce = 0
        tAnterior = int(time.time())
        while self.seguir:
            timeStamp = int(time.time())
            if not timeStamp == tAnterior:
                nonce = 0
            bloqueAux["time-stamp"] = timeStamp
            bloqueAux["nonce"] = nonce
            hash = self.obtener_hash_de_bloque(bloqueAux)
            if self.comprobar_prueba_de_trabajo(hash, dificultad):
                bloqueMinado = bloqueAux
                break
            tAnterior = timeStamp
            nonce += 1
        return bloqueMinado #O es un type bool (bloque no minado) o es el bloque minado

    def comprobar_prueba_de_trabajo(self, hash:str, dificultad:str):#VERSION1.2
        # print("Comprobamos si el hash cumple la dificultad.", hash, dificultad)
        return int(hash,16) <= int(dificultad,16) # Si el hash es menor o igual a la dificultad entonces True

    def hash(self, string:str) -> str:#VERSION1.2
        # print("Aplicamos el algoritmo sha256 a un string.", string)
        # Aplica el algoitmo sha256 a un string puede ser (clave publica, bloque, transaccion)
        return hashlib.sha256(string.encode('utf-8')).hexdigest()

    def validar_transaccion(self, transaccion, esHash=False, esComision=False, esCoinbase=False, coinbase = 100):#VERSION1.2

        if esHash:
            transaccion = self.trasacciones[transaccion]
        
        print("validamos si la transaccion es correcta", transaccion)


        if esCoinbase:
            return ((((len(transaccion) >= 3 and \
                    "time-stamp" in transaccion) and \
                    "emisor" in transaccion) and \
                    transaccion["cantidad"] == coinbase) and \
                    transaccion["emisor"] == "0000000000000000000000000000000000000000000000000000000000000000")

        if esComision: #Si es comision, no se tiene que comprobar la firma
            return (((len(transaccion) >= 3 and \
                    "time-stamp" in transaccion) and \
                    "emisor" in transaccion) and \
                    "cantidad" in transaccion)   
        
        mensaje = self.crear_mensaje(transaccion["emisor"], transaccion["receptor"], transaccion["cantidad"])
        
        clave_publica = serialization.load_pem_public_key(
            transaccion["clave-publica"].encode('utf-8'),
            backend=default_backend()
        )

        firma = base64.b64decode(transaccion["firma"])

        esValida = self.crear_direccion(transaccion["clave-publica"]) == transaccion["emisor"]
        print("Miramos que la firma sea valida.")
        try:
            clave_publica.verify(
                firma,
                mensaje.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("La firma es válida.")
        except InvalidSignature:
            esValida = False
            print("La firma no es válida.")
        
        return esValida

    def validar_bloque(self, bloqueConHash, hash_anterior):#VERSION1.2
        """
        Esta funcion valida un bloque, puede ser que el bloque sea nuestro o que sea de otro nodo.
        Se supone que si el bloqueConHash no tiene el atributo "propagador" quiere decir que el
        bloque es nuestro y que tenemos toda la informacion necesaria para validar el bloque.
        """
        print("Vamos a validar un bloque.", bloqueConHash, hash_anterior)
        bloque = bloqueConHash["bloque"]
        valido = True
        if not bloque["hash-anterior"] == hash_anterior:
            valido = False
        hash = self.obtener_hash_de_bloque(bloque)
        if not bloqueConHash["hash"] == hash:
            valido = False

        print("Vamos a calcular la recompensa del bloque.", bloque["indice"])
        recompensa = self.recompensa_bloque(bloque["indice"])
        for transaccion in bloque["transacciones"]:
            t = transaccion
            if not t in self.trasaccionesDeEnvio and not "propagador" in bloqueConHash:
                return False
            elif "propagador" in bloqueConHash:
                aux = bloqueConHash["propagador"]
                print("No tenemos la transaccion de envio, la pedimos al nodo que nos ha enviado el bloque.", t, aux)
                taux = requests.get(f"http://{aux}/obtener_transaccion_de_envio?t={t}")
                if taux.status_code == 200:
                    self.trasaccionesDeEnvio[t] = taux.json()
                    for i in self.trasaccionesDeEnvio[t]:
                        if not i == "transaccionesQuemadas":
                            if not self.trasaccionesDeEnvio[t][i] in self.trasacciones:
                                aux = bloqueConHash["propagador"]
                                tt = self.trasaccionesDeEnvio[t][i]
                                taux = requests.get(f"http://{aux}/obtener_transaccion?t={tt}")
                                if taux.status_code == 200:
                                    self.trasacciones[self.trasaccionesDeEnvio[t][i]] = taux.json()
                                    #ESTO SE DEBERIA DE HACER SI LA CADENA QUE NOS MANDAN ES CORRECTA
                                    # self.trasaccionesNoQuemadas[self.trasaccionesDeEnvio[t][i]] = self.trasacciones[self.trasaccionesDeEnvio[t][i]]

                    if "transaccionesQuemadas" in self.trasaccionesDeEnvio[t]:
                        for i in self.trasaccionesDeEnvio[t]["transaccionesQuemadas"]:
                            if not self.trasaccionesDeEnvio[t][i] in self.trasacciones:
                                aux = bloqueConHash["propagador"]
                                tt = self.trasaccionesDeEnvio[t][i]
                                print("No tenemos la transaccion, la pedimos al nodo que nos ha enviado el bloque.", tt, aux)
                                taux = requests.get(f"http://{aux}/obtener_transaccion?t={tt}")
                                if taux.status_code == 200:
                                    self.trasacciones[self.trasaccionesDeEnvio[t][i]] = taux.json()
                                    #ESTO SE DEBERIA DE HACER SI LA CADENA QUE NOS MANDAN ES CORRECTA
                                    # self.trasaccionesNoQuemadas[self.trasaccionesDeEnvio[t][i]] = self.trasacciones[self.trasaccionesDeEnvio[t][i]]

                else:
                    return False
        
            if not self.validar_transaccion_envio(self.trasaccionesDeEnvio[t], coinbase=recompensa):
                valido = False
                break

        if not self.comprobar_prueba_de_trabajo(hash, bloque["dificultad"]):
            valido = False

        # Si el bloque es válido, agregarlo a la cadena
        if valido:
            if not hash in self.bloques:
                self.bloques[hash] = bloque
            print("Bloque válido")
        else:
            print("Bloque NO válido")
        
        return valido


    def obtener_hash_de_bloque(self, bloque):#VERSION1.2
        # print("Obtenemos el hash de un bloque.", bloque)
        return self.hash(str(bloque))

    def agregar_nodo(self, ipNodo):#VERSION1.2
        print("Añadimos un nodo a la lista de nodos conocidos.", ipNodo)
        # ipNodo = "localhost:5000"
        self.nodos.add(ipNodo)
        return self.nodos

    def calcular_dificultad(self):#VERSION1.2
        """
        Tiene que mirar los ultimos 10 bloques y calcular la dificultad del siguiente bloque,
        para ello necesita los 10 bloques al bloque que se quiere calcular.
        Solo calcular la dificultad para los bloques con id multiplo de 10, empezando por el 10.
        Para calcular la dificultad del bloque 16 por ejemplo solo habria que poner la del 15, porque hasta el 20
        no se vuelve a actualizar la dificultad.

        HAY QUE TENER EN CUENTA QUE NOS PASARAN LA CADENA HASTA 1 BLOQUE ANTES DEL QUE QUEREMOS CALCULAR
        """
        print("Calculamos la dificultad del siguiente bloque.")
        if (self.bloques[self.cadenaDeBloques[-1]]["indice"] + 1) % 10 == 0:
            #Calcular la dificultad
            if len(self.cadenaDeBloques) < 10:
                return False
            lapsus = self.bloques[self.cadenaDeBloques[-1]]["time-stamp"] - self.bloques[self.cadenaDeBloques[-10]]["time-stamp"]
            if lapsus <= 600: # Si se a tardado menos de 10 minutos en minar los 10 bloques se aumenta la dificultad por 2 (desplazar un bit a la derecha)
                print("Como se ha tardado menos de 10 minutos en minar los 10 bloques se aumenta la dificultad por 2 (desplazar un bit a la derecha)")
                return hex(int(self.bloques[self.cadenaDeBloques[-1]]["dificultad"], 16) >> 1)
            else: # En caso contrario se disminuye la dificultad por 2 (mover un bit a la izquierda, y sumar 1)
                print("Como se ha tardado mas de 10 minutos en minar los 10 bloques se disminuye la dificultad por 2 (mover un bit a la izquierda, y sumar 1)")
                return hex(int((self.bloques[self.cadenaDeBloques[-1]]["dificultad"], 16) << 1) + 1)
                
        else:
            print("La diciultad del siguiente bloque es la misma que la del ultimo bloque.", self.bloques[self.cadenaDeBloques[-1]]["dificultad"])
            return self.bloques[self.cadenaDeBloques[-1]]["dificultad"]
    
    def validar_dificultad(self, cadenaDeBloques):#VERSION1.2
        """
        Solo son necesarios los ultimos 11 bloques para validar la dificultad del ultimo bloque,
        esto es por si el ultimo bloque es el 10, 20, 30, etc.
        """
        print("Vamos a validar la dificultad del ultimo bloque de la cadena de bloques.", cadenaDeBloques)
        if self.bloques[cadenaDeBloques[-1]]["indice"] <= 9:
            return self.bloques[cadenaDeBloques[-1]]["dificultad"] == self.dificultadInicial #0x00000fff...ff
        elif len(cadenaDeBloques) < 11:
            return False
        else:
            if self.bloques[cadenaDeBloques[-1]]["indice"] % 10 == 0:
                lapsus = self.bloques[cadenaDeBloques[-2]]["time-stamp"] - self.bloques[cadenaDeBloques[-11]]["time-stamp"]
                if lapsus <= 600: 
                    return hex(int(self.bloques[cadenaDeBloques[-2]]["dificultad"], 16) >> 1) == self.bloques[cadenaDeBloques[-1]]["dificultad"]
                else: 
                    return hex(int((self.bloques[cadenaDeBloques[-2]]["dificultad"], 16) << 1) + 1) == self.bloques[cadenaDeBloques[-1]]["dificultad"]
                    
            else:
                return self.bloques[cadenaDeBloques[-1]]["dificultad"] == self.bloques[cadenaDeBloques[-2]]["dificultad"]
    
    def validar_dificultad_cadena_entera(self, cadenaDeBloques):#VERSION1.2
        print("Vamos a validar la dificultad de la cadena entera.", cadenaDeBloques)
        for i in range(1, len(cadenaDeBloques)):
            if not self.validar_dificultad(cadenaDeBloques[max(0, i-11):i]):#Asi solo se le pasan las 11 ultimas
                return False
        return True

    def validar_cadena(self, cadenaConPropagador):#VERSION1.2
        # Comprobar que la cadena es válida
        print("Vamos a validar la cadena de bloques.", cadenaConPropagador)
        cadena = cadenaConPropagador["cadena"]
        if not cadena[0] in self.bloques:
            aux = cadenaConPropagador["propagador"]
            print("No tenemos el bloque genesis, lo pedimos al nodo que nos ha enviado la cadena.", aux, cadena[0])
            baux = requests.get(f"http://{aux}/obtener_bloque?b={cadena[0]}")
            if baux.status_code == 200:
                a = baux.json()
                if a:
                    self.bloques[cadena[0]] = a
                else:
                    return False
            else:
                return False
        if not self.validar_bloque_genesis(self.bloques[cadena[0]]):
            return False

        for i in range(1, len(cadena)):
            if not cadena[i] in self.bloques:
                aux = cadenaConPropagador["propagador"]
                print("No tenemos el bloque", cadena[i], "lo pedimos al nodo que nos ha enviado la cadena.", aux)
                baux = requests.get(f"http://{aux}/obtener_bloque?b={cadena[i]}")
                if baux.status_code == 200:
                    a = baux.json()
                    if a:
                        self.bloques[cadena[i]] = a
                    else:
                        return False
                else:
                    return False
            if not self.validar_bloque({"bloque":self.bloques[cadena[i]], "hash": cadena[i]}, cadena[i-1]["hash"]):
                return False
        
        if not self.validar_dificultad_cadena_entera(cadena):
            return False

        return True

    def reemplazar_cadena(self, nueva_cadenaConPropagador):#VERSION1.2 #Falta terminar
        print("Nos piden reemplazar nuestra cadena de bloques por la que nos han enviado.", nueva_cadenaConPropagador)
        print("Nuestra cadena es:", self.cadenaDeBloques)
        # Reemplazar la cadena actual por la nueva en caso de que sea válida y mas larga (si es igual nos quedamos con la nuestra)
        if len(nueva_cadenaConPropagador["cadena"]) > len(self.cadenaDeBloques):
            if self.validar_cadena(nueva_cadenaConPropagador):
                #TODO: HACER UNA FUNCION PARA REEMPLAZAR LA CADENA, QUE TENGA EN CUENTA LAS TRANSACCIONES QUEMADAS etc.
                print("La cadena es valida y mas larga, la reemplazamos.")
                self.cadenaDeBloques = nueva_cadenaConPropagador["cadena"]
                #Si hemos cambiado nuestra cadena, tenemos que parar el minado del bloque que estamos haciendo
                self.seguir = False
                #Si hemos cambiado nuestra cadena, tenemos que propagarla a los demas nodos
                self.propagar_cadena()
                return True
        print("o la cadena no es valida o no es mas larga, no la reemplazamos.")
        return False

    def propagar_cadena(self):#VERSION1.2
        print("Propagamos la cadena de bloques a todos los nodos conocidos.")
        cambiados, noCambiados = 0, 0
        for nodo in self.nodos:
            # Enviar la cadena a todos los nodos
            print("Intentamos propagar la cadena al nodo: " + nodo + ".")
            x = requests.post(f"http://{nodo}/reemplazar_cadena", json = {"cadena":self.cadenaDeBloques, "propagador":"localhost:"+str(self.puerto)}) #¿Provisional lo de localHost?
            if x.status_code == 200 and x.text == "True":
                print("Hemos propagado la cadena al nodo: " + nodo + ".")
                print("El nodo ha cambiado su cadena.")
                cambiados += 1
            elif x.status_code == 200 and x.text == "False":
                print("Hemos propagado la cadena al nodo: " + nodo + ".")
                print("El nodo NO ha cambiado su cadena.")
                noCambiados += 1
            else:
                print("Error al propagar la cadena al nodo: " + nodo)
        
        return cambiados, noCambiados

    def propagar_transaccion(self, transaccion):#VERSION1.2
        #Cuando se llame a la ruta añadir transaccion
        #Llamar a "anadir_transaccion" y a esta funcion una vez la hayamos guardado
        print("Propagamos la transaccion a todos los nodos conocidos.", transaccion)
        enviados, errorAlEnviar = 0, 0
        for nodo in self.nodos:
            # Enviar la transacción a todos los nodos
            print("Intentamos propagar la transaccion al nodo: " + nodo + ".")
            x = requests.post(f"http://{nodo}/anadir_transaccion", json = transaccion) #¿Provisional lo de localHost?
            if x.status_code == 200:
                print("Hemos propagado la transaccion al nodo: " + nodo + ".")
                enviados += 1
            else:
                print("Error al propagar la transaccion al nodo: " + nodo)
                errorAlEnviar += 1
        
        return enviados, errorAlEnviar
                

    #Estas 3 funciones se usan para obtener la informacion de una transaccion o bloque que solo tengamos su identificador
    def obtener_info_transaccion(self, hash):#VERSION1.2
        print("Nos piden la informacion de la transaccion.", hash)
        if hash in self.trasacciones:
            print("Devolvemos la informacion de la transaccion.", self.trasacciones[hash])
            return self.trasacciones[hash]
        else:
            print("No tenemos la informacion de la transaccion.")
            return False

    def obtener_info_transaccion_envio(self, hash):#VERSION1.2
        print("Nos piden la informacion de la transaccion de envio.", hash)
        if hash in self.trasaccionesDeEnvio:
            print("Devolvemos la informacion de la transaccion de envio.", self.trasaccionesDeEnvio[hash])
            return self.trasaccionesDeEnvio[hash]
        else:
            print("No tenemos la informacion de la transaccion de envio.")
            return False

    def obtener_info_bloque(self, hash):#VERSION1.2
        print("Nos piden la informacion del bloque.", hash)
        if hash in self.bloques:
            print("Devolvemos la informacion del bloque.", self.bloques[hash])
            return self.bloques[hash]
        else:
            print("No tenemos la informacion del bloque.")
            return False