
from elliptic_curves import BinaryFieldEllipticCurve, PrimeFieldEllipticCurve, inverse_mod
import random

# Prime field parameters
print("Prime Curve Testing")
p =  1098437885977
n = 1098438026893
a = -3
b = 12380
curve = PrimeFieldEllipticCurve(p=p, a=a, b=b, n=n)
x1 = random.randrange(2,(n-1))
P = curve.find_next_point(x1)
x,y = P
print(f"Random Point 1 = ({x:#x}, {y:#x})")
x2 = random.randrange(2,(n-1))
G = curve.find_next_point(x2)
x,y = G
print(f"Random Point 2 = ({x:#x}, {y:#x})")
print("Solving Pollard's Rho for the two points...")
k = curve.pollards_rho(P,G)
if k is not None:
    print("Pollard Rho found P->G multiplier =", hex(k))
else:
    print("No Solution")
    exit()

curve.G = P
R=curve.scalar_mult(k,P)
x,y = R
print("Testing ECDSA with these points")
print(f"Public Key Point = ({x:#x}, {y:#x})")
message = "Special Message"
d=k
k=random.randrange(2,n-1)
sig=curve.ecdsa_sign(message,d,k)
r,s = sig
print(f"Signature = ({r:#x}, {s:#x})")
print("Verify signature = ", curve.ecdsa_verify(message, sig, R) )


#Use Binary Curves to test features
print("\nBinary Curve Testing")

a=1
b=51
m=37
poly_coeffs = [ m, 7,6,3,0]
n=68719407787

curve_binary = BinaryFieldEllipticCurve(m=m, poly_coeffs=poly_coeffs, a=a, b=b, n=n)
#Generate random generator point (you should do this more carefully)
#x1 = random.randrange(2,n-1)
G = (0xf9bd91741, 0x1ec7717d74) #curve_binary.find_next_point(x1)
curve_binary.G= G
x,y = G
#Random Point 1 = (0xf9bd91741, 0x1ec7717d74)
#Random Point 2 = (0xcb65be65e, 0xe6fdb25e0)
print(f"Random Point 1 = ({x:#x}, {y:#x})")
print("Is on curve? ", curve_binary.is_on_curve(G))

#Genreate another random point
#x2 = random.randrange(2,n-1)
Q = (0xcb65be65e, 0xe6fdb25e0) #curve_binary.find_next_point(x2)
x,y = Q
print(f"Random Point 2 = ({x:#x}, {y:#x})")
print("Is on curve? ", curve_binary.is_on_curve(Q))


#Try to find the multiplier to get from G to Q (this will take a few minutes)
print("Solving Pollard's Rho for the two points...")
k = 0x61f0ae891 #curve_binary.pollards_rho(G,Q)
if k is not None:
    print("Pollard Rho found G->Q multiplier =", hex(k))
else:
    print("No Solution, Sorry try again")
    exit()

#Use the discovered k as the private key multiplier to get a new Public Key Point P
P=curve_binary.scalar_mult(k,G)
x,y = P
#Note this should be the same as Q above
print("Testing ECDSA with these points")
print(f"Public Key = ({x:#x}, {y:#x})")

#Test using these points for ECDSA
message = "Special Message"
d=k
k=random.randrange(2,(n-1) >> 1 )
sig=curve_binary.ecdsa_sign(message,d,k)
r,s = sig
print(f"Signature = ({r:#x}, {s:#x})")
print("Verify signature = ", curve_binary.ecdsa_verify(message, sig, P) )

