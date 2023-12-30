class Blockchain():

    # importar librerias
    import hashlib
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.exceptions import InvalidSignature
    import base64

    def __init__(self) -> None:
        self.cadenaDeBloques = [] # Lista de bloques
        self.trasacciones = {} # Diccionario de transacciones existentes {hash:transaccion} 
        self.mempool = [] # Lista de transacciones pendientes
        self.nodos = set() # Conjunto de nodos conectados

    def validar_transaccion(self, transaccion):

        #PASAR LOS str DE LA TRANSACCION A SIGNATURE Y PUBLIC_KEY
        #MIRAR SI LA FIRMA COINCIDE A ESA PUBLIC_KEY

        # Validar la transacción
        # Si es válida, agregarla al mempool
        # Si no es válida, descartarla
        self.mempool.append(transaccion)

    def validar_bloque(self, bloque, hash_anterior):
        valido = True
        if bloque.hash_anterior != hash_anterior:
            valido = False
        if bloque.hash != self.calcular_hash(bloque):
            valido = False
        for transaccion in bloque.transacciones:
            if not self.validar_transaccion(transaccion):
                valido = False
        # Validar el bloque
        # Si es válido, agregarlo a la cadena
        # Si no es válido, descartarlo

        # Si el bloque es válido, agregarlo a la cadena
        self.cadena.append(bloque)

