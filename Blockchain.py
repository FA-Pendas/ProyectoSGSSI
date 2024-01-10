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

    #VERSION 1.2: Mirar los detalles en el cuarderno

    #No se pueden borrar las transacciones una vez se han añadido a la mempool

    #DIFICULTAD:
    # a = "0x" + "f"*64

    # print(a)

    # a = int(a, 16) Pasar de hexadecimal a entero

    # print(a)

    # a = hex(a) Pasar de entero a hexadecimal	

    # print(a)

    # a = a>>4 Desplazar 4 bits a la derecha

    def __init__(self, puerto = 5000, direccion = "0x0000000000000000000000000000000000000000000000000000000000000000") -> None:#VERSION1.2
        
        self.seguir = True # Para parar el minado actual
        self.puerto = puerto # Puerto del nodo

        self.direccion = direccion # Direccion del nodo

        self.bloques = {} # Diccionario de bloques {hash:bloque}
        self.cadenaDeBloques = [] # Lista de hashes de bloques

        self.trasaccionesDeEnvio = {} # Diccionario de transacciones de envio #VERSION1.1
#       {hash:{
#           "enviado": hash       
#           "sobras": hash
#           "comision": hash
#       }}

        #SI EN TRANSACCIONES ESTAN YA TODAS LAS TRANSACCIONES, transaccionesNoQuemadas PUEDE SER SOLO UNA LISTA
        self.trasacciones = {} # Diccionario de transacciones existentes {hash:transaccion}
        self.trasaccionesNoQuemadas = {} # Diccionario de transacciones no quemadas {hash:transaccion}
        
        self.mempool = [] # Lista de listas de transacciones de envio pendientes

        #TODO: dos diccionarios, uno que me diga una transaccion en que transaccion de envio esta y otro diccionario que me diga en que bloque esta una transaccion de envio
        #PUEDE ESTAR MUY BIEN PARA SABER EN QUE BLOQUE Y SITIO ESTA CADA COSA TENIENDO SOLO EL IDENTIFICADOR DE UNA TRANSACCION

        self.nodos = set() # Conjunto de nodos conectados

    def bloqueGenesis(self):
        #El bloque genesis no tiene transacciones
        dificultad = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" #0x0000fff...ff
    
    def validar_bloque_genesis(self, bloque):#VERSION1.2
        return bloque["indice"] == 0 and \
                bloque["dificultad"] == "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" and \
                bloque["hash-anteriror"] == "0x0000000000000000000000000000000000000000000000000000000000000000" and \
                "time-stamp" in bloque and \
                "nonce" in bloque and \
                len(bloque) == 5 and \
                self.comprobar_prueba_de_trabajo(self.obtener_hash_de_bloque(), bloque["dificultad"])

    def hola(self):
        print("Hola")
        return None

    def crear_direccion(self, public_key:str) -> str:#VERSION1.2
        return self.hash(public_key)

    def crear_mensaje(self, emisor:str, receptor:str, cantidad:int) -> str:#VERSION1.2
        return f"{emisor} {receptor} {cantidad}"

    def firmar(self, private_key:str, mensaje:str, contrasena:str = None) -> str:#VERSION1.2
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

    def crear_transaccion(self, public_key:str, private_key:str, emisor:str, receptor:str, cantidad:float, comision:float, transaccionesAQuemar:list[str], contrasena:str = None):#VERSION1.2
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

    def crear_una_transaccion_sobra(self, timeStamp, emisor, cantidad):#VERSION1.2
        
        return {#TODO: para cuando el minero se quede con la comision: transaccion.pop("receptor", None)
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
        return { #TIENE QUE TENER ESTE ORDEN
            "time-stamp": timeStamp, # O int(time.time())
            "emisor": emisor,
            "receptor": receptor,
            "cantidad": float(cantidad),
            "firma": firma,
            "clave-publica": public_key # Dejar la clave publica en str
        }

    def validar_transaccion_no_quemada(self, transaccion:str, emisor:str) -> bool:#VERSION1.2
        return transaccion in self.trasaccionesNoQuemadas and self.trasaccionesNoQuemadas[transaccion].receptor == emisor
    
    def validar_transaccion_envio(self, transaccion, esHash = False):#VERSION1.2

        #Siempre las voy a tener almacenadas?

        if esHash:
            transaccion = self.trasaccionesDeEnvio[transaccion]

        #Tiene que tener al menos una transaccion y las transacciones quemadas
        valido = (len(transaccion) >= 2 and "enviado" in transaccion) and "transaccionesQuemadas" in transaccion

        #Todos los campos de la transaccion tienen que ser validos
        for i in transaccion:
            if i not in ["enviado","sobras","comision", "transaccionesQuemadas"]:
                valido = False
                break
            else:
                if i == "enviado":
                    if not self.validar_transaccion(transaccion[i], esHash=True):
                        valido = False
                        break
                elif i == "sobras":
                    if not self.validar_transaccion(transaccion[i], esHash=True):
                        valido = False
                        break
                elif i == "comision":
                    if not self.validar_transaccion(transaccion[i], esHash=True, esComision=True):
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
    def anadir_transaccion(self, transaccion: dict) -> str:#VERSION1.2 # transaccionesAQuemar: list
        #Da igual que tengamos la info
        transaccionAux = deepcopy(transaccion)
        if self.validar_transaccion_envio(transaccion):
            for i in transaccion:
                if not i == "transaccionesQuemadas":
                    h = self.obtener_hash_de_transaccion(transaccion[i])
                    self.trasacciones[h] = transaccion[i]
                    transaccionAux[i] = h

            h = self.obtener_hash_de_transaccion(transaccionAux)
            self.trasaccionesDeEnvio[h] = transaccionAux

            if h not in self.mempool:
                self.mempool.append(h)#Propagar la transaccion a los demas nodos
                self.propagar_transaccion(transaccion)
                return h
            else:
                return False#Delvolver False para que si ya la tenemos no la propaguemos a los nodos que conocemos?
        return False
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

    def obtener_hash_de_transaccion(self, transaccion):#VERSION1.2
        #Sirve para los dos tipos de transaccion, la individual y la de envio
        return self.hash(str(transaccion))

    def obtener_dificultad(self):#VERSION1.2 #TODO: MIRAR SI ELIMNAR ESTA Y USAR LA DE CALCULAR DIFICULTAD Y MIRAR SI QUITAR PARAMETRO DE CALCULAR DIFICULTAD Y QUE PILLE EL self.cadenaDeBloques
        return self.ultimo_bloque().dificultad # TODO: esto hay que cambiarlo, que cambie cada 10 bloques?

    def crear_bloque(self, hash_anterior):#, transacciones):#VERSION1.2
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
            # "hash": "0x356435345" ESTE HASH IGUAL NO HAY QUE INCLUIRLO AQUI
        }

    def ultimo_bloque(self):#VERSION1.2
        return self.bloques[self.cadenaDeBloques[-1]]
    
    def minar(self, bloque):#VERSION1.2
        """
        Aqui se le pide que mine 1 bloque, TODO: HACER ESTA FUNCION COMO LA QUE SE VA A EJECUTAR SIEMPRE EN EL HILO? no, que se llame desde otra funcion que sea el hilo, que tenga while true
        """
        bloqueMinado = False
        dificultad = bloque.dificultad
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
        return int(hash,16) <= int(dificultad,16) # Si el hash es menor o igual a la dificultad entonces True

    def hash(self, string:str) -> str:#VERSION1.2
        # Aplica el algoitmo sha256 a un string puede ser (clave publica, bloque, transaccion)
        return hashlib.sha256(string.encode('utf-8')).hexdigest()

    def validar_transaccion(self, transaccion, esHash=False, esComision=False):#VERSION1.2
        #TODO: Mirar que la clave publica corresponde con el emisor
        if esHash:
            transaccion = self.trasacciones[transaccion]

        if esComision: #Si es comision, no se tiene que comprobar la firma
            return (((len(transaccion) >= 3 and \
                    "time-stamp" in transaccion) and \
                    "emisor" in transaccion) and \
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

    def validar_bloque(self, bloqueConHash, hash_anterior):#VERSION1.2
        """
        Esta funcion valida un bloque, puede ser que el bloque sea nuestro o que sea de otro nodo.
        Se supone que si el bloqueConHash no tiene el atributo "propagador" quiere decir que el
        bloque es nuestro y que tenemos toda la informacion necesaria para validar el bloque.
        """
        bloque = bloqueConHash.bloque
        valido = True
        if not bloque["hash-anterior"] == hash_anterior:
            valido = False
        hash = self.obtener_hash_de_bloque(bloque)
        if not bloqueConHash.hash == hash:
            valido = False
        for transaccion in bloque.transacciones:
            t = transaccion
            if not t in self.trasaccionesDeEnvio and not "propagador" in bloqueConHash:
                return False
            elif "propagador" in bloqueConHash:
                taux = requests.get(f"http://{bloqueConHash.propagador}/obtener_transaccion_de_envio?t={t}") #TODO: HACER UNA PETICION AL NODO PARA QUE NOS DE LA TRANSACCION
                #TODO: SI PIDO UNA TRANSACCION DE ENVIO TAMBIEN PEDIR LAS TRANSACCIONES O VIENEN CON TODA LA INFO?
                #TODO
                #TODO
                if taux.status_code == 200:#TODO: COMPROBAR QUE SIEMPRE QUE ES CORRECTO DEVUELVE 200, ¿COMPROBAR QUE ES MENOR QUE 400?
                    self.trasaccionesDeEnvio[t] = taux.json()
                else:
                    return False
            if not self.validar_transaccion_envio(self.trasaccionesDeEnvio[t]):
                valido = False
                break

        if not self.comprobar_prueba_de_trabajo(hash, bloque.dificultad):
            valido = False
        # TODO: COMPROBAR QUE LA DIFICULTAD DEL BLOQUE ES LA CORRECTA? - abria que recorrer toda la blockchain

        # Si el bloque es válido, agregarlo a la cadena
        if valido:
            #self.cadenaDeBloques.append(hash) NO HAY QUE AÑADIRLO, DESPUES DE VALIDARLO YA SE VERA SI SE AÑADE O NO
            if not hash in self.bloques:
                self.bloques[hash] = bloque
            print("Bloque válido")
        else:
            print("Bloque no válido")
        
        return valido


    def obtener_hash_de_bloque(self, bloque):#VERSION1.2
        return self.hash(str(bloque))

    def agregar_nodo(self, ipNodo):#VERSION1.2
        self.nodos.add(ipNodo)
        return self.nodos

    def calcular_dificultad(self, cadenaDeBloques):#VERSION1.2
        """
        Tiene que mirar los ultimos 10 bloques y calcular la dificultad del siguiente bloque,
        para ello necesita los 10 bloques al bloque que se quiere calcular.
        Solo calcular la dificultad para los bloques con id multiplo de 10, empezando por el 10.
        Para calcular la dificultad del bloque 16 por ejemplo solo habria que poner la del 15, porque hasta el 20
        no se vuelve a actualizar la dificultad.

        HAY QUE TENER EN CUENTA QUE NOS PASARAN LA CADENA HASTA 1 BLOQUE ANTES DEL QUE QUEREMOS CALCULAR
        """
        if (self.bloques[cadenaDeBloques[-1]].indice + 1) % 10 == 0:
            #Calcular la dificultad
            if len(cadenaDeBloques) < 10:
                return False
            lapsus = self.bloques[cadenaDeBloques[-1]]["time-stamp"] - self.bloques[cadenaDeBloques[-10]]["time-stamp"]
            if lapsus <= 600: # Si se a tardado menos de 10 minutos en minar los 10 bloques se aumenta la dificultad por 2 (desplazar un bit a la derecha)
                return hex(int(self.bloques[cadenaDeBloques[-1]].dificultad, 16) >> 1)
            else: # En caso contrario se disminuye la dificultad por 2 (mover un bit a la izquierda, y sumar 1)
                return hex(int((self.bloques[cadenaDeBloques[-1]].dificultad, 16) << 1) + 1)
                
        else:
            return self.bloques[cadenaDeBloques[-1]].dificultad
    
    def validar_dificultad(self, cadenaDeBloques):#VERSION1.2
        """
        Solo son necesarios los ultimos 11 bloques para validar la dificultad del ultimo bloque,
        esto es por si el ultimo bloque es el 10, 20, 30, etc.
        """
        if self.bloques[cadenaDeBloques[-1]].indice <= 9:
            return self.bloques[cadenaDeBloques[-1]].dificultad == "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" #0x0000fff...ff
        elif len(cadenaDeBloques) < 11:
            return False
        else:
            if self.bloques[cadenaDeBloques[-1]].indice % 10 == 0:
                lapsus = self.bloques[cadenaDeBloques[-2]]["time-stamp"] - self.bloques[cadenaDeBloques[-11]]["time-stamp"]
                if lapsus <= 600: 
                    return hex(int(self.bloques[cadenaDeBloques[-2]].dificultad, 16) >> 1) == self.bloques[cadenaDeBloques[-1]].dificultad
                else: 
                    return hex(int((self.bloques[cadenaDeBloques[-2]].dificultad, 16) << 1) + 1) == self.bloques[cadenaDeBloques[-1]].dificultad
                    
            else:
                return self.bloques[cadenaDeBloques[-1]].dificultad == self.bloques[cadenaDeBloques[-2]].dificultad
    
    def validar_dificultad_cadena_entera(self, cadenaDeBloques):#VERSION1.2
        for i in range(1, len(cadenaDeBloques)):
            if not self.validar_dificultad(cadenaDeBloques[max(0, i-11):i]):#Asi solo se le pasan las 11 ultimas
                return False
        return True


    #TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
        # IDEA V.1.2 La idea que voy a intentar va a ser pasar solo los hashes y en caso de no tenerlos pedirlos
        # PROPONERSE HACERLO ENVIANDO LOS HASHES DE LOS BLOQUES Y LAS TRANSACCIONES - en tal caso habria que crear rutas para pedir bloques, transacciones, etc

    #TODO: POR SIMPLICIDAD SE PASARA TODA LA INFORMACION, SE PODRIAN PASAR TODOS LOS HASHES Y EN CASO DE NO TENER ESA INFORMACION PEDIRLA - PERO ES MAS TEDIOSO
    def validar_cadena(self, cadenaConPropagador):#VERSION1.2
        # Comprobar que la cadena es válida
        cadena = cadenaConPropagador.cadena
        if not cadena[0] in self.bloques:
            baux = requests.get(f"http://{cadenaConPropagador.propagador}/obtener_bloque?b={cadena[0]}") #TODO: HACER UNA PETICION AL NODO PARA QUE NOS DE LA TRANSACCION
            if baux.status_code == 200:#TODO: COMPROBAR QUE SIEMPRE QUE ES CORRECTO DEVUELVE 200, ¿COMPROBAR QUE ES MENOR QUE 400?
                self.bloques[cadena[0]] = baux.json()
            else:
                return False
        if not self.validar_bloque_genesis(self.bloques[cadena[0]]):
            return False

        for i in range(1, len(cadena)):
            if not cadena[i] in self.bloques:
                baux = requests.get(f"http://{cadenaConPropagador.propagador}/obtener_bloque?b={cadena[i]}") #TODO: HACER UNA PETICION AL NODO PARA QUE NOS DE LA TRANSACCION
                if baux.status_code == 200:#TODO: COMPROBAR QUE SIEMPRE QUE ES CORRECTO DEVUELVE 200, ¿COMPROBAR QUE ES MENOR QUE 400?
                    self.bloques[cadena[i]] = baux.json()
                else:
                    return False
            if not self.validar_bloque({"bloque":self.bloques[cadena[i]], "hash": cadena[i]}, cadena[i-1].hash):
                return False
        
        return True

    def reemplazar_cadena(self, nueva_cadenaConPropagador):#VERSION1.2 #Falta terminar
        # TODO: NOS LLEGA UNA CADENA DE BLOQUES CON TODOS LOS DATOS, NO SOLO LOS HASHES - EN CASO DE REEMPLAZARLA TENER EN CUENTA TODO LO QUE HAY QUE HACER posiblemente eliminar 
        # Reemplazar la cadena actual por la nueva en caso de que sea válida y mas larga (si es igual nos quedamos con la nuestra)
        if len(nueva_cadenaConPropagador.cadena) > len(self.cadenaDeBloques):
            if self.validar_cadena(nueva_cadenaConPropagador):
                #TODO: HACER UNA FUNCION PARA REEMPLAZAR LA CADENA, QUE TENGA EN CUENTA LAS TRANSACCIONES QUEMADAS etc.
                self.cadenaDeBloques = nueva_cadenaConPropagador.cadena
                #Si hemos cambiado nuestra cadena, tenemos que parar el minado del bloque que estamos haciendo
                self.seguir = False
                #Si hemos cambiado nuestra cadena, tenemos que propagarla a los demas nodos
                self.propagar_cadena()
                return True
        return False

    def propagar_cadena(self):#VERSION1.2
        cambiados, noCambiados = 0, 0
        for nodo in self.nodos:
            # Enviar la cadena a todos los nodos
            x = requests.post(f"http://{nodo}/reemplazar_cadena", json = {"cadena":self.cadenaDeBloques, "propagador":"localhost:"+self.puerto}) #¿Provisional lo de localHost?
            if x.status_code == 200 and x.text == "True":
                cambiados += 1
            elif x.status_code == 200 and x.text == "False":
                noCambiados += 1
            else:
                print("Error al propagar la cadena al nodo: " + nodo)
        
        return cambiados, noCambiados

    def propagar_transaccion(self, transaccion):#VERSION1.2
        #Cuando se llame a la ruta añadir transaccion
        #Llamar a "anadir_transaccion" y a esta funcion una vez la hayamos guardado
        enviados, errorAlEnviar = 0, 0
        for nodo in self.nodos:
            # Enviar la transacción a todos los nodos
            x = requests.post(f"http://{nodo}/anadir_transaccion", json = transaccion) #¿Provisional lo de localHost?
            if x.status_code == 200:
                enviados += 1
            else:
                errorAlEnviar += 1
        
        return enviados, errorAlEnviar
                

    #Estas 3 funciones se usan para obtener la informacion de una transaccion o bloque que solo tengamos su identificador
    def obtener_info_transaccion(self, hash):#VERSION1.2
        if hash in self.trasacciones:
            return self.trasacciones[hash]
        else:
            return False

    def obtener_info_transaccion_envio(self, hash):#VERSION1.2
        if hash in self.trasaccionesDeEnvio:
            return self.trasaccionesDeEnvio[hash]
        else:
            return False

    def obtener_info_bloque(self, hash):#VERSION1.2
        if hash in self.bloques:
            return self.bloques[hash]
        else:
            return False