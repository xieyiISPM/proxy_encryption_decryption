import random
from phe import paillier

k= 5
modular = 2** 5

x = random.getrandbits(k)
x2 = random.getrandbits(k)

x1 = (x - x2) % modular

reconsX = (x1 + x2) % modular

y = random.getrandbits(k)
y2 = random.getrandbits(k)

y1 = (y - y2) % modular

reconsY = (y1 + y2) % modular

print("x", x)
print("x2", x2)
print("x1", x1)
print("reconsX", reconsX)

print("y", y)
print("y2", y2)
print("y1", y1)
print("reconsY", reconsY)

print()
print("Addition verification")
z1 = (x1+ y1) % modular
z2 = (x2 + y2)% modular
z = (z1 + z2) % modular

reconsZ = (x + y) % modular

print("z", z)
print("z2", z2)
print("z1", z1)
print("reconsZ", reconsZ)

print()
print("Multiplication verification")

# get arithmetic multiplication
a = random.getrandbits(k)
a2 = random.getrandbits(k)
a1 = (a-a2) % modular

b = random.getrandbits(k)
b2 = random.getrandbits(k)
b1 = (b - b2) % modular

r = random.getrandbits(k)
c2 =((a2*b2) -r) % modular

public_key, private_key = paillier.generate_paillier_keypair()
cypherA1 = public_key.raw_encrypt(a1)
cypherB1 = public_key.raw_encrypt(b1)

print("cypher a1", cypherA1)
print("cypher b1", cypherB1)

d = ((cypherA1 **b1) % public_key.nsquare)*((cypherB1**a1) % public_key.nsquare) * (public_key.encrypt(r)) % public_key.nsquare
c1 = a1*b1 + private_key.decrpt(d)


c1 = (a1 + b1 +(b2*a1+a2*b1+r) % modular) % modular

e1 = (x1-a1) % modular
f1 = (y1-b1) % modular
e2 = (x2-a2) % modular
f2 = (y2-b2) % modular

e = (e1 + e2) % modular
f = (f1 + f2) % modular

z1 = (1*e*f + f*a1 + e*b1 + c1) % modular
z2 = (0*e*f + f*a2 + e*b2 +c2) % modular

reconsZ = (z1 + z2) % modular
z = (x*y) % modular

print("z", z)
print("z2", z2)
print("z1", z1)
print("reconsZ", reconsZ)











