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
        
        self.nodos = set() # Conjunto de nodos conectados

    def hola(self):
        print("Hola")
        return None

    def crear_direccion(self, public_key:str):#VERSION1.0
        return hash(public_key)

    def crear_mensaje(self, emisor:str, receptor:str, cantidad:int):#VERSION1.0
        return f"{emisor} {receptor} {cantidad}"

    def firmar(self, private_key:str, mensaje:str, contrasena:str = None):#VERSION1.0
        private_key_from_str = serialization.load_pem_private_key(
            private_key.encode('utf-8'),
            password=contrasena,
            backend=default_backend()
        )
        signature = private_key.sign(
            mensaje,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def crear_transaccion(self, public_key:str, private_key:str, mensaje:str, contrasena:str = None):#VERSION1.0
        
        #Obtenemos el receptor, emisor y cantidad del mensaje
        emisor, receptor, cantidad = mensaje.split(" ")

        #Convertimos la clave publica a un objeto de tipo public_key
        public_key_from_str = serialization.load_pem_public_key(
            public_key.encode('utf-8'),
            backend=default_backend()
        )

        #Firmamos el mensaje
        firma = self.firmar(private_key, mensaje, contrasena)

        #Devolvemos la transaccion
        return { #TIENE QUE TENER ESTE ORDEN
            "time-stamp": time.time(), # O int(time.time())
            "emisor": emisor,
            "receptor": receptor,
            "cantidad": float(cantidad),
            "firma": firma,
            "clave-publica": public_key_from_str
        }

    def validar_transaccion_no_quemada(self, transaccion, emisor):#VERSION1.0
        return self.trasaccionesNoQuemadas[transaccion].receptor == emisor

    # TODO: SE AÑADEN MAS DE UNA TRANSACCION A LA VEZ (son dependientes entre ellas)
    # TODO: Que en la mempool haya listas con transacciones que se tienen que minar juntas
    # TODO: El restante se le pasa al emisor
    # LAS TRANSACCIONES QUE SON DE UNA PERSONA A ELLA MISMA NO SE TIENEN QUE FIRMAR, SON RESIDUOS Y SON VALIDOS
    # TODO: PARA SIMPLIFICAR QUE LA CANTIDAD QUE SE LE PASA A LA GENTE SEA LA TOTAL DE LAS TRANSACCIONES QUE SE VAN A QUEMAR
    def anadir_transaccion(self, transaccion: dict, transaccionesAQuemar: list):#VERSION1.0
        cantidad = 0
        for i in transaccionesAQuemar:
            if self.validar_transaccion_no_quemada(i, transaccion.emisor):
                cantidad += self.trasaccionesNoQuemadas[i].cantidad
        
        if cantidad < transaccion.cantidad:
            return False
        
        #Eliminar las transacciones a quemar de la lista de transacciones no quemadas
        for i in transaccionesAQuemar:
            if self.validar_transaccion_no_quemada(i, transaccion.emisor):
                self.trasaccionesNoQuemadas.pop(i)
        # Transacciones a quemar es una lista de transacciones que se van a quemar en esta transaccion
        # El sobrante se le pasara a la direccion del emisor
        if self.validar_transaccion(transaccion):
            self.mempool.append(transaccion)
            #TODO: Cuando se añada a la cadena, quitarla del mempool y hacerle el hash en modo string para que el hash sea la clave en el diccionario de transacciones

    def obtener_hash_de_transaccion(self, transaccion):#VERSION1.0
        return self.hash(str(transaccion))

    def obtener_dificultad(self):#VERSION1.0
        return self.ultimo_bloque().dificultad # TODO: esto hay que cambiarlo, que cambie cada 10 bloques?

    def crear_bloque(self, hash_anterior):#, transacciones):#VERSION1.0
        # Crear un bloque
        # añadir todas las transacciones del mempool al bloque (todavia no borrarlas del mempool)
        transacciones = []
        for i in self.mempool: # En la mempool solo hay transacciones validas
            for j in i:
                transacciones.append(self.obtener_hash_de_transaccion(j))

        bloque = {
            "indice": self.ultimo_bloque().indice + 1,
            "transacciones": transacciones,
            "dificultad": self.obtener_dificultad(),
            "hash-anterior": self.ultimo_bloque().hash
            #TIENE QUE SER EN ESTE ORDEN
            # "time-stamp": 1357425863,
            # "nonce": 0,
            # "hash": "0x356435345"
        }
        pass

    def ultimo_bloque(self):#VERSION1.0
        return self.bloques[self.cadenaDeBloques[-1]]
    
    def minar(self, bloque):#VERSION1.0
        # Una vez el bloque es valido, se mina
        pass

    def hash(self, string:str):#VERSION1.0
        # Aplica el algoitmo sha256 a un string puede ser (clave publica, bloque, transaccion)
        return hashlib.sha256(string.encode('utf-8')).hexdigest()

    def validar_transaccion(self, transaccion, esHash=False):#VERSION1.0

        if esHash:
            transaccion = self.trasacciones[transaccion]
        
        mensaje = self.crear_mensaje(transaccion.emisor, transaccion.receptor, transaccion.cantidad)
        
        clave_publica = serialization.load_pem_public_key(
            transaccion["clave-publica"].encode('utf-8'),
            backend=default_backend()
        )

        firma = base64.b64decode(transaccion.firma)

        esValida = True

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

    def validar_bloque(self, bloque, hash_anterior):#VERSION1.0
        valido = True
        if bloque.hash_anterior != hash_anterior:
            valido = False
        if bloque.hash != self.calcular_hash(bloque):
            valido = False
        for transaccion in bloque.transacciones:
            if not self.validar_transaccion(self.transacciones[transaccion]):
                valido = False
                break
        # CALCULAR EL HASH DEL BLOQUE Y COMPARAR QUE SOBREPASA LA DIFICULTAD
        # COMPROBAR QUE LA DIFICULTAD DEL BLOQUE ES LA CORRECTA?

        # Si el bloque es válido, agregarlo a la cadena
        if valido:
            h = self.obtener_hash_de_bloque(bloque)
            self.cadenaDeBloques.append(h)
            self.bloques[h] = bloque
        else:
            print("Bloque no válido")


    def obtener_hash_de_bloque(self, bloque):#VERSION1.0
        return self.hash(str(bloque))

    def agregar_nodo(self, ipNodo):#VERSION1.0
        self.nodos.add(ipNodo)

    def agregar_transaccion(self, transaccion):#TODO: Borrar esta funcion#VERSION1.0
        if self.validar_transaccion(transaccion):
            self.mempool.append(transaccion)
        else:
            print("Transacción no válida")

    def reemplazar_cadena(self, nueva_cadena):#VERSION1.0
        # Reemplazar la cadena actual por la nueva en caso de que sea válida y mas larga (si es igual nos quedamos con la nuestra)
        pass

    def propagar_cadena(self, cadena):#VERSION1.0
        for nodo in self.nodos:
            # Enviar la cadena a todos los nodos
            pass

    def propagar_transaccion(self, transaccion):#VERSION1.0
        for nodo in self.nodos:
            # Enviar la transacción a todos los nodos
            pass