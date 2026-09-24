from keygen import RSAKeyPair, keygen

def mod(m,e,n) :
    res_mod = 1
    base = m % n
    pow_e = []
    while e > 0:
        pow_e.append(e % 2)
        e = e // 2

    for i in range(len(pow_e)):
        if(pow_e[i] == 1):
            res_mod = (res_mod * base) % n
        base = (base * base) % n
        
    return res_mod

def encrypt(m, e, n):
    return mod(m, e, n)

def decrypt(c, d, n):
    return mod(c, d, n)

def text_to_int(text):
    text = text.encode()
    return int.from_bytes(text)

def int_to_text(i):
    length_of_bits = ((i.bit_length() + 7) // 8) 
    return int.to_bytes(i ,length_of_bits).decode()


