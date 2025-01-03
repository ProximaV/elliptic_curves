
from elliptic_curves import BinaryFieldEllipticCurve, PrimeFieldEllipticCurve, test_prime_order
import random

# Prime field parameters
print("Prime Curve Testing")
p =  1098437885977
n = 1098438026893
a = -3
b = 12380
curve = PrimeFieldEllipticCurve(p=p, a=a, b=b, n=n)
x1 = random.randrange(2,(p-1))
P = curve.find_next_point(x1)
x,y = P
print(f"Random Point 1 = ({x:#x}, {y:#x})")
x2 = random.randrange(2,(p-1))
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
message = "The Message (said in the Critical Drinker's voice)"
d=k
sig=curve.ecdsa_sign(message,d) #let it generate a secure nonce
r,s = sig
print(f"Signature = ({r:#x}, {s:#x})")
print("Verify signature = ", curve.ecdsa_verify(message, sig, R) )


#Use Binary Curves to test features
print("\nBinary Curve Testing (NIST Curve B-233)")
'''
# Use this Curve if you want to experiment with Binary Pollard Rho
a=1
b=51
m=37
poly_coeffs = [ m, 7,6,3,0]
n=68719407787
'''
# Note that you shouldn't run Pollard Rho on this curve....

a=1
b=0x066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD
m=233
poly_coeffs = [m,74,0]
n=0x1000000000000000000000000000013E974E72F8A6922031D2603CFE0D7
G = ( 0x0FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B , 0x1006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052 ) #(0xf9bd91741, 0x1ec7717d74) #curve_binary.find_next_point(x1)

curve_binary = BinaryFieldEllipticCurve(m=m, poly_coeffs=poly_coeffs, a=a, b=b, n=n, G=G)
#Generate random generator point (you should do this more carefully)
#x1 = random.randrange(2,n-1)

print("Testing G = ", test_prime_order(curve_binary,G,n))

x,y = G
#Random Point 1 = (0xf9bd91741, 0x1ec7717d74)
#Random Point 2 = (0xcb65be65e, 0xe6fdb25e0)
print(f"Generator Point 1 = ({x:#x}, {y:#x})")
print("Is on curve? ", curve_binary.is_on_curve(G))

#Genreate another random point
#x2 = random.randrange(2,n-1)
Q = (0x1caeabf7c8ace883794a51be31a62798305dab82500bfe7f2b84aad4756, 0x57640d127d93aa735797e9cec7f9a83f291959b4d0a3ba507199b03e8c) #(0xcb65be65e, 0xe6fdb25e0) #curve_binary.find_next_point(x2)


x,y = Q
print(f"Random Point 2 = ({x:#x}, {y:#x})")
print("Is on curve? ", curve_binary.is_on_curve(Q))


#Try to find the multiplier to get from G to Q (this will take a few minutes)
#print("Solving Pollard's Rho for the two points...")
k =  0x7f460df4fbd2f95beb66f408a267716ce0cf97a0cbefe96fb30557ed6a #0x61f0ae891 #curve_binary.pollards_rho(G,Q)
#if k is not None:
#    print("Pollard Rho found G->Q multiplier =", hex(k))
#else:
#    print("No Solution, Sorry try again")
#    exit()

#Use the discovered k as the private key multiplier to get a new Public Key Point P
P=curve_binary.scalar_mult(k,G)
x,y = P
#Note this should be the same as Q above
print("Testing ECDSA with these points")
print(f"Public Key = ({x:#x}, {y:#x})")

#Test using these points for ECDSA
message = "The Message (said in the Critical Drinker's voice)"
d=k
sig=curve_binary.ecdsa_sign(message,d) # let it generate a secure nonce
r,s = sig
print(f"Signature = ({r:#x}, {s:#x})")
print("Verify signature = ", curve_binary.ecdsa_verify(message, sig, P) )

