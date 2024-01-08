# importar librerias
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
import base64
import time

class Blockchain():

    def __init__(self) -> None:
        self.bloques = {} # Diccionario de bloques {hash:bloque}
        self.cadenaDeBloques = [] # Lista de hashes de bloques
        self.trasacciones = {} # Diccionario de transacciones existentes {hash:transaccion}
        self.trasaccionesNoQuemadas = {} # Diccionario de transacciones no quemadas {hash:transaccion} 
        self.mempool = [] # Lista de listas de transacciones pendientes
        self.nodos = set() # Conjunto de nodos conectados

    def hola(self):
        print("Hola")
        return None

    def crear_direccion(self, public_key:str):
        return hash(public_key)

    def crear_mensaje(self, emisor:str, receptor:str, cantidad:int):
        return f"{emisor} {receptor} {cantidad}"

    def firmar(self, private_key:str, mensaje:str, contrasena:str = None):
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

    def crear_transaccion(self, public_key:str, private_key:str, mensaje:str, contrasena:str = None):
        
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

    # TODO: SE AÑADEN MAS DE UNA TRANSACCION A LA VEZ (son dependientes entre ellas)
    # TODO: Que en la mempool haya listas con transacciones que se tienen que minar juntas
    def anadir_transaccion(self, transaccion, transaccionesAQuemar):
        # Transacciones a quemar es una lista de transacciones que se van a quemar en esta transaccion
        # El sobrante se le pasara a la direccion del emisor
        if self.validar_transaccion(transaccion):
            self.mempool.append(transaccion)
            #TODO: Cuando se añada a la cadena, quitarla del mempool y hacerle el hash en modo string para que el hash sea la clave en el diccionario de transacciones

    def obtener_hash_de_transaccion(self, transaccion):
        return self.hash(str(transaccion))

    def obtener_dificultad(self):
        return self.ultimo_bloque().dificultad # TODO: esto hay que cambiarlo, que cambie cada 10 bloques?

    def crear_bloque(self, hash_anterior):#, transacciones):
        # Crear un bloque
        # añadir todas las transacciones del mempool al bloque (todavia no borrarlas del mempool)
        transacciones = []
        for i in self.mempool: # En la mempool solo hay transacciones validas
            transacciones.append(self.obtener_hash_de_transaccion(i))

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

    def ultimo_bloque(self):
        return self.bloques[self.cadenaDeBloques[-1]]
    
    def minar(self, bloque):
        # Una vez el bloque es valido, se mina
        pass

    def hash(self, string:str):
        # Aplica el algoitmo sha256 a un string puede ser (clave publica, bloque, transaccion)
        return hashlib.sha256(string.encode('utf-8')).hexdigest()

    def validar_transaccion(self, transaccion, esHash=False):

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

    def validar_bloque(self, bloque, hash_anterior):
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


    def obtener_hash_de_bloque(self, bloque):
        return self.hash(str(bloque))

    def agregar_nodo(self, ipNodo):
        self.nodos.add(ipNodo)

    def agregar_transaccion(self, transaccion):#TODO: Borrar esta funcion
        if self.validar_transaccion(transaccion):
            self.mempool.append(transaccion)
        else:
            print("Transacción no válida")

    def reemplazar_cadena(self, nueva_cadena):
        # Reemplazar la cadena actual por la nueva en caso de que sea válida y mas larga (si es igual nos quedamos con la nuestra)
        pass

    def propagar_cadena(self, cadena):
        for nodo in self.nodos:
            # Enviar la cadena a todos los nodos
            pass

    def propagar_transaccion(self, transaccion):
        for nodo in self.nodos:
            # Enviar la transacción a todos los nodos
            pass