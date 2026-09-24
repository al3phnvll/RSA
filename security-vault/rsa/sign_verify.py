from encrypt_decrypt import *

def sign(m,d,n):
    return mod(m,d,n)

def verify(s,e,n):
    return mod(s,e,n)

kp = keygen()
m = text_to_int("hi")
s = sign(m, kp.d, kp.n)
recovered = verify(s, kp.e, kp.n)
print(int_to_text(recovered))