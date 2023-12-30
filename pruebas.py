#La b lo vuelve en bytes
a = 'a'
a = bytes(a, 'utf-8')
b = b"a"
print(a[0]>>6, b[0]>>6)