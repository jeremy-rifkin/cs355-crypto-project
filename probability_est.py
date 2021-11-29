from mpmath import mp

mp.dps = 100

def prob(d, g):
	domain = mp.mpf(d)
	guesses = mp.mpf(g)
	p = 1 - mp.factorial(guesses) * mp.binomial(domain, guesses) / domain ** guesses
	print(p)

print("SHA-256 1E6  guesses", end=" "); prob(2**256, 1E6)
print("SHA-256 1E30 guesses", end=" "); prob(2**256, 1E30)
print("31m coin flips      ", end=" "); print(1/(mp.mpf(2)**31.25E6))
print("31m weighted flips  ", end=" "); print(mp.mpf(.99)**31.25E6)
print("Protocol, 2b runs   ", end=" "); prob(2**128, 1E9)
