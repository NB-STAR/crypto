from gmpy2 import *

def PollardRho_p_1(N):
	a = i = 2
	while 1:
		a = pow(a, i, N)
		d = gcd(a - 1, N)
		if d != 1:
			return d
		i += 1
		

N = 90685199108317803042380434438490356019921472822283817856556932210253825019082211404991083156291938268

print PollardRho_p_1(N)