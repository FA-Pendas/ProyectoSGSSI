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

class Blockchain():
    #No se pueden borrar las transacciones una vez se han añadido a la mempool

    #DIFICULTAD:
    # a = "0x" + "f"*64

    # print(a)

    # a = int(a, 16) Pasar de hexadecimal a entero

    # print(a)

    # a = hex(a) Pasar de entero a hexadecimal	

    # print(a)

    # a = a>>4 Desplazar 4 bits a la derecha

    def __init__(self, direccion = "0x0000000000000000000000000000000000000000000000000000000000000000") -> None:
        
        self.direccion = direccion # Direccion del nodo

        self.bloques = {} # Diccionario de bloques {hash:bloque}
        self.cadenaDeBloques = [] # Lista de hashes de bloques

        self.trasaccionesDeEnvio = {} # Diccionario de transacciones de envio #VERSION1.1
#       {hash:{
#           "enviado": hash       
#           "sobras": hash
#           "comision": hash
#       }}

        self.trasacciones = {} # Diccionario de transacciones existentes {hash:transaccion}
        self.trasaccionesNoQuemadas = {} # Diccionario de transacciones no quemadas {hash:transaccion} 
        
        self.mempool = [] # Lista de listas de transacciones de envio pendientes

        #TODO: dos diccionarios, uno que me diga una transaccion en que transaccion de envio esta y otro diccionario que me diga en que bloque esta una transaccion de envio
        #PUEDE ESTAR MUY BIEN PARA SABER EN QUE BLOQUE Y SITIO ESTA CADA COSA TENIENDO SOLO EL IDENTIFICADOR DE UNA TRANSACCION

        self.nodos = set() # Conjunto de nodos conectados

    def hola(self):
        print("Hola")
        return None

    def crear_direccion(self, public_key:str) -> str:#VERSION1.1
        return self.hash(public_key)

    def crear_mensaje(self, emisor:str, receptor:str, cantidad:int) -> str:#VERSION1.1
        return f"{emisor} {receptor} {cantidad}"

    def firmar(self, private_key:str, mensaje:str, contrasena:str = None) -> str:#VERSION1.1
        private_key_from_str = serialization.load_pem_private_key(
            private_key.encode('utf-8'),
            password=contrasena,
            backend=default_backend()
        )
        signature = private_key_from_str.sign(
            mensaje,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def crear_transaccion(self, public_key:str, private_key:str, emisor:str, receptor:str, cantidad:float, comision:float, transaccionesAQuemar:list[str], contrasena:str = None):#VERSION1.1
        c = 0
        transaccionesQuemadas = []
        for i in transaccionesAQuemar:
            if self.validar_transaccion_no_quemada(i, emisor):
                c += self.trasaccionesNoQuemadas[i].cantidad
                transaccionesQuemadas.append(i)

        #Hay que crear las 3 o 2 o 1 transaccion
        timeStamp = int(time.time()) #AQUI SE CREA EL TIMESTAMP

        if c < cantidad:
            return False
        elif c == cantidad:
            #Crear solo 1 transaccion
            mensaje = self.crear_mensaje(emisor, receptor, cantidad)
            transaccion = self.crear_una_transaccion(public_key, private_key, mensaje, timeStamp, contrasena)
            return {"enviado":transaccion, #"sobras":None, "comision":None}
                    "transaccionesQuemadas":transaccionesQuemadas}

        elif c == (cantidad + comision):
            #Crear 2 transacciones
            mensajeE = self.crear_mensaje(emisor, receptor, cantidad)
            transaccionE = self.crear_una_transaccion(public_key, private_key, mensajeE, timeStamp, contrasena)

            transaccionC = self.crear_una_transaccion_sobra(timeStamp, emisor, comision)

            return {"enviado":transaccionE, 
                    "comision":transaccionC,#"sobras":None}
                    "transaccionesQuemadas":transaccionesQuemadas}
            
        elif c > cantidad and comision == 0:
            #Crear 2 transacciones
            mensajeE = self.crear_mensaje(emisor, receptor, cantidad)
            transaccionE = self.crear_una_transaccion(public_key, private_key, mensajeE, timeStamp, contrasena)

            mensajeS = self.crear_mensaje(emisor, emisor, c-cantidad)
            transaccionS = self.crear_una_transaccion(public_key, private_key, mensajeS, timeStamp, contrasena)

            return {"enviado":transaccionE, 
                    "sobras":transaccionS,#"comision":None}
                    "transaccionesQuemadas":transaccionesQuemadas}
            
        else:
            #Crear 3 transacciones
            mensajeE = self.crear_mensaje(emisor, receptor, cantidad)
            transaccionE = self.crear_una_transaccion(public_key, private_key, mensajeE, timeStamp, contrasena)
        
            transaccionC = self.crear_una_transaccion_sobra(timeStamp, emisor, comision)

            mensajeS = self.crear_mensaje(emisor, emisor, c-(cantidad+comision))
            transaccionS = self.crear_una_transaccion(public_key, private_key, mensajeS, timeStamp, contrasena)

            return {"enviado":transaccionE, 
                    "sobras":transaccionS,
                    "comision":transaccionC,
                    "transaccionesQuemadas":transaccionesQuemadas}

    def crear_una_transaccion_sobra(self, timeStamp, emisor, cantidad):#VERSION1.1
        
        return {#TODO: para cuando el minero se quede con la comision: transaccion.pop("receptor", None)
            "time-stamp": timeStamp,
            "emisor": emisor,
            "cantidad": cantidad,
        }

    def crear_una_transaccion(self, public_key:str, private_key:str, mensaje:str, timeStamp:float,contrasena:str = None):#VERSION1.1
        
        #Obtenemos el receptor, emisor y cantidad del mensaje
        emisor, receptor, cantidad = mensaje.split(" ")

        #Firmamos el mensaje
        firma = self.firmar(private_key, mensaje, contrasena)

        #Devolvemos la transaccion
        return { #TIENE QUE TENER ESTE ORDEN
            "time-stamp": timeStamp, # O int(time.time())
            "emisor": emisor,
            "receptor": receptor,
            "cantidad": float(cantidad),
            "firma": firma,
            "clave-publica": public_key # Dejar la clave publica en str
        }

    def validar_transaccion_no_quemada(self, transaccion, emisor):#VERSION1.1
        return transaccion in self.trasaccionesNoQuemadas and self.trasaccionesNoQuemadas[transaccion].receptor == emisor
    
    def validar_transaccion_envio(self, transaccion, esHash = False):#VERSION1.1

        if esHash:
            transaccion = self.trasaccionesDeEnvio[transaccion]

        #Tiene que tener al menos una transaccion y las transacciones quemadas
        valido = len(transaccion) >= 2 and "enviado" in transaccion

        #Todos los campos de la transaccion tienen que ser validos
        for i in transaccion:
            if i not in ["enviado","sobras","comision", "transaccionesQuemadas"]:
                valido = False
                break
            else:
                if i == "enviado":
                    if not self.validar_transaccion(transaccion[i]):
                        valido = False
                        break
                elif i == "sobras":
                    if not self.validar_transaccion(transaccion[i]):
                        valido = False
                        break
                elif i == "comision":
                    if not self.validar_transaccion(transaccion[i], esComision=True):
                        valido = False
                        break
                elif i == "transaccionesQuemadas":
                    for j in transaccion[i]:
                        if not self.validar_transaccion_no_quemada(j, transaccion["enviado"]["emisor"]):
                            valido = False
                            break

        return valido

    # TODO: SE AÑADEN MAS DE UNA TRANSACCION A LA VEZ (son dependientes entre ellas)
    # TODO: Que en la mempool haya listas con transacciones que se tienen que minar juntas
    # TODO: El restante se le pasa al emisor
    # LAS TRANSACCIONES QUE SON DE UNA PERSONA A ELLA MISMA NO SE TIENEN QUE FIRMAR, SON RESIDUOS Y SON VALIDOS
    # TODO: PARA SIMPLIFICAR QUE LA CANTIDAD QUE SE LE PASA A LA GENTE SEA LA TOTAL DE LAS TRANSACCIONES QUE SE VAN A QUEMAR
    def anadir_transaccion(self, transaccion: dict):#VERSION1.1 # transaccionesAQuemar: list
        
        if self.validar_transaccion_envio(transaccion):
            for i in transaccion:
                if not i == "transaccionesQuemadas":
                    h = self.obtener_hash_de_transaccion(transaccion[i])
                    self.trasacciones[h] = transaccion[i]
                    transaccion[i] = h

            h = self.obtener_hash_de_transaccion(transaccion)
            self.trasaccionesDeEnvio[h] = transaccion

            self.mempool.append(h)
            return h
        ########################################################################################################################
        # cantidad = 0
        # transaccionesAQuemar = transaccion["transaccionesQuemadas"]
        # for i in transaccionesAQuemar:
        #     if self.validar_transaccion_no_quemada(i, transaccion.emisor):
        #         cantidad += self.trasaccionesNoQuemadas[i].cantidad
        #     else:
        #         return False # Si alguna transaccion esta quemada o no es del emisor, la transaccion no es valida
        


        # if cantidad < transaccion.cantidad:
        #     return False
        
        # #Eliminar las transacciones a quemar de la lista de transacciones no quemadas
        # for i in transaccionesAQuemar:
        #     if self.validar_transaccion_no_quemada(i, transaccion.emisor):
        #         self.trasaccionesNoQuemadas.pop(i)
        # # Transacciones a quemar es una lista de transacciones que se van a quemar en esta transaccion
        # # El sobrante se le pasara a la direccion del emisor
        # if self.validar_transaccion(transaccion):
        #     self.mempool.append(transaccion)
        #     #TODO: Cuando se añada a la cadena, quitarla del mempool y hacerle el hash en modo string para que el hash sea la clave en el diccionario de transacciones
        ########################################################################################################################

    def obtener_hash_de_transaccion(self, transaccion):#VERSION1.1
        #Sirve para los dos tipos de transaccion, la individual y la de envio
        return self.hash(str(transaccion))

    def obtener_dificultad(self):#VERSION1.1
        return self.ultimo_bloque().dificultad # TODO: esto hay que cambiarlo, que cambie cada 10 bloques?

    def crear_bloque(self, hash_anterior):#, transacciones):#VERSION1.0
        # Crear un bloque
        # añadir todas las transacciones del mempool al bloque (todavia no borrarlas del mempool)
        # transacciones = []
        # for i in self.mempool: 
        #     transacciones.append(i)

        return {# Se envia el bloque con la informacion necesaria para que el minero lo mine
            "indice": self.ultimo_bloque().indice + 1,
            "transacciones": self.mempool, # En la mempool solo hay transacciones validas
            "dificultad": self.obtener_dificultad(),
            "hash-anterior": self.ultimo_bloque().hash
            #TIENE QUE SER EN ESTE ORDEN
            # "time-stamp": 1357425863,
            # "nonce": 0,
            # "hash": "0x356435345"
        }

    def ultimo_bloque(self):#VERSION1.1
        return self.bloques[self.cadenaDeBloques[-1]]
    
    def minar(self, bloque):#VERSION1.0
        # Una vez el bloque es valido, se mina
        pass

    def hash(self, string:str) -> str:#VERSION1.1
        # Aplica el algoitmo sha256 a un string puede ser (clave publica, bloque, transaccion)
        return hashlib.sha256(string.encode('utf-8')).hexdigest()

    def validar_transaccion(self, transaccion, esHash=False, esComision=False):#VERSION1.1
        #TODO: Mirar que la clave publica corresponde con el emisor
        if esHash:
            transaccion = self.trasacciones[transaccion]

        if esComision: #Si es comision, no se tiene que comprobar la firma
            return ((((len(transaccion) == 4 and \
                    "time-stamp" in transaccion) and \
                    "emisor" in transaccion) and \
                    "receptor" in transaccion) and \
                    "cantidad" in transaccion)   
        
        mensaje = self.crear_mensaje(transaccion.emisor, transaccion.receptor, transaccion.cantidad)
        
        clave_publica = serialization.load_pem_public_key(
            transaccion["clave-publica"].encode('utf-8'),
            backend=default_backend()
        )

        firma = base64.b64decode(transaccion.firma)

        esValida = self.crear_direccion(transaccion["clave-publica"]) == transaccion.emisor

        try:
            clave_publica.verify(
                firma,
                mensaje,
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

    def validar_bloque(self, bloque, hash_anterior):#VERSION1.1
        valido = True
        if not bloque.hash_anterior == hash_anterior:
            valido = False
        hash = self.obtener_hash_de_bloque(bloque)
        if not bloque.hash == hash:
            valido = False
        for transaccion in bloque.transacciones:
            if not self.validar_transaccion_envio(self.trasaccionesDeEnvio[transaccion]):
                valido = False
                break

        if int(hash,16) < int(transaccion.dificultad,16):
            valido = False
        # TODO: COMPROBAR QUE LA DIFICULTAD DEL BLOQUE ES LA CORRECTA? - abria que recorrer toda la blockchain

        # Si el bloque es válido, agregarlo a la cadena
        if valido:
            h = self.obtener_hash_de_bloque(bloque)
            self.cadenaDeBloques.append(h)
            self.bloques[h] = bloque
        else:
            print("Bloque no válido")
        
        return valido


    def obtener_hash_de_bloque(self, bloque):#VERSION1.1
        return self.hash(str(bloque))

    def agregar_nodo(self, ipNodo):#VERSION1.1
        self.nodos.add(ipNodo)


    #TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
        # PROPONERSE HACERLO ENVIANDO LOS HASHES DE LOS BLOQUES Y LAS TRANSACCIONES - en tal caso habria que crear rutas para pedir bloques, transacciones, etc

    #TODO: POR SIMPLICIDAD SE PASARA TODA LA INFORMACION, SE PODRIAN PASAR TODOS LOS HASHES Y EN CASO DE NO TENER ESA INFORMACION PEDIRLA - PERO ES MAS TEDIOSO
    def validar_cadena(self, cadena):#VERSION1.0
        #TODO: AUNQUE ALMACENEMOS LOS HASHES EN LA LISTA DE LOS BLOQUES LO QUE NOS PASAN ES LA LISTA DE LOS BLOQUES CON TODA LA INFORMACION
        # Comprobar que la cadena es válida
        pass

    def reemplazar_cadena(self, nueva_cadena):#VERSION1.0
        # TODO: NOS LLEGA UNA CADENA DE BLOQUES CON TODOS LOS DATOS, NO SOLO LOS HASHES - EN CASO DE REEMPLAZARLA TENER EN CUENTA TODO LO QUE HAY QUE HACER posiblemente eliminar 
        # Reemplazar la cadena actual por la nueva en caso de que sea válida y mas larga (si es igual nos quedamos con la nuestra)
        pass

    def propagar_cadena(self, cadena):#VERSION1.0
        # TODO: GENERAR LA CADENA ENTERA 
        for nodo in self.nodos:
            # Enviar la cadena a todos los nodos
            pass

    def propagar_transaccion(self, transaccion):#VERSION1.0
        for nodo in self.nodos:
            # Enviar la transacción a todos los nodos
            pass