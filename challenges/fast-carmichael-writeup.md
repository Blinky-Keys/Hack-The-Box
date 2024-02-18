# Fast Carmichael Writeup

You are walking with your friends in search of sweets and discover a mansion in the distance. All your friends are too scared to approach the building, so you go on alone. As you walk down the street, you see expensive cars and math papers all over the yard. Finally, you reach the door. The doorbell says "Michael Fastcar". You recognise the name immediately because it was on the news the day before. Apparently, Fastcar is a famous math professor who wants to get everything done as quickly as possible. He has even developed his own method to quickly check if a number is a prime. The only way to get candy from him is to pass his challenge.

## Files Provided

- `server.py`

## Challenge Script

```python
from secret import FLAG
from Crypto.Util.number import isPrime
import socketserver
import signal

class Handler(socketserver.BaseRequestHandler):

	def handle(self):
		signal.alarm(0)
		main(self.request)

class ReusableTCPServer(socketserver.ForkingMixIn, socketserver.TCPServer):
	pass

def sendMessage(s, msg):
	s.send(msg.encode())

def receiveMessage(s, msg):
	sendMessage(s, msg)
	return s.recv(4096).decode().strip()

def generate_basis(n):
	basis = [True] * n

	for i in range(3, int(n**0.5) + 1, 2):
		if basis[i]:
			basis[i * i::2 * i] = [False] * ((n - i * i - 1) // (2 * i) + 1)
	return [2] + [i for i in range(3, n, 2) if basis[i]]

def millerRabin(n, b):
	basis = generate_basis(300)
	if n == 2 or n == 3:
		return True

	if n % 2 == 0:
		return False

	r, s = 0, n - 1
	while s % 2 == 0:
		r += 1
		s //= 2
	for b in basis:
		x = pow(b, s, n)
		if x == 1 or x == n - 1:
			continue
		for _ in range(r - 1):
			x = pow(x, 2, n)
			if x == n - 1:
				break
			else:
				return False
	return True

def _isPrime(p):
	if p < 1:
		return False
	if not millerRabin(p, 300):
		return False
		
	return True

def main(s):
	p = receiveMessage(s, "Give p: ")

	try:
		p = int(p)
	except:
		sendMessage(s, "Error!")

	if _isPrime(p) and not isPrime(p):
		sendMessage(s, FLAG)
	else:
		sendMessage(s, "Conditions not satisfied!")

if __name__ = '__main__':
	socketserver.TCPServer.allow_reuse_address = True
	server = ReusableTCPServer(("0.0.0.0", 1337), Handler)
	server.serve_forever()
```

The script we're given looks rather complicated, but it boils down to a pretty simple condition that we have to satisfy before we're given the flag. 

## Prime and Not Prime?

If we look at the `main` function of the script, we can see the following lines of code:

```python
if _isPrime(p) and not isPrime(p):
    sendMessage(s, FLAG)
else:
    sendMessage(s, "Conditions not satisfied!")
```

At first glance, this doesn't really make a lot of sense. How can a number simultaneously be a prime number, and not a prime number? Well that depends on how we're testing the primality of that number. 

We can see that there are two different functions that are being used here:

- `_isPrime()`
- `isPrime()`

The `isPrime()` function is being imported from `Crypto.Util.number`, whereas the `_isPrime()` function is being defined within the `server.py` script itself:

```python
def _isPrime(p):
	if p < 1:
		return False
	if not millerRabin(p, 300):
		return False
		
	return True
```

It looks like the `_isPrime()` function is using the [Miller-Rabin Primality Test](https://en.wikipedia.org/wiki/Miller–Rabin_primality_test) to determine if the number passed in is a prime. 

So, putting all of this together, we can see that we need to supply a number that will be determined to be a prime by the Miller-Rabin test, and determined to be a *non-prime* by the python `Crypto` library (also called `pycryptodome). 

## Miller-Rabin Test

So what is the Miller-Rabin test? The Miller-Rabin test is a *probabilistic* primality test that determines whether or not a number is *likely* to be prime. It's essentially an automated educated guess that gets more accurate as the time you spend running the test goes up. Because the test is *probabilistic*, there is a chance that it will produce false positives, stating that a given number is prime when in fact it is not. That is the result that we want to produce here. 

### Test Operation

To test the primality of a number $n$, we record the value of $n-1$ as $2^sd$, where $s$ is a positive integer and $d$ is a positive *odd* integer. We then choose a *base* number that is co-prime to $n$. A number is considered co-prime to another number when they share no common factors with each other except $1$. 

We then check if either of the following congruence relations hold:

$$a^d \equiv 1 \pmod n$$

$$a^{2^rd} \equiv -1 \pmod n \ \ \ 0 \leq r < s$$

If either of these relations does hold, we pick a new base a repeat the test. The more rounds of testing we perform, we more confident we can be that $n$ is a prime. So how do we mess with this? Enter Carmichael numbers. 

## Carmichael Numbers

Carmichael numbers are composite numbers (i.e. non-prime) that satisfy the following congruence relation:

$$b^n \equiv b \pmod n$$

We can rewrite the relation like so:

$$b^{n-1} \equiv 1 \pmod n$$

Notice that this looks very similar to one of the relations used by the Miller-Rabin test:

$$a^d \equiv 1 \pmod n$$

Because Carmichael numbers satisfy the same congruence relation that is used by the Miller-Rabin test, we can likely use one of them to fool it and get our flag. On the Carmichael number [wikipedia page](https://en.wikipedia.org/wiki/Carmichael_number#Overview), there is a section that details a number that is determined as a "`strong pseudoprime to all prime bases less than 307`". Take a look at the `millerRabin` function in our `server.py` and see that it is using all bases less than 300:

```python
def millerRabin(n, b):
	basis = generate_basis(300)
```

Looks like this number is going to work, but what is its actual value?

## Big Math

If we read the [wikipedia page](https://en.wikipedia.org/wiki/Carmichael_number#Overview) a little, we get given a formula for calculating this magic number:

$$N=p*(313*(p-1)+1)*(353*(p-1)+1)$$

We also get given the value of $p$:

$$p=29674495668685510550154174642905332730771991799853043350995075531276838753171770199594238596428121188033664754218345562493168782883$$

Obviously this number is going to be huge, so we should use a script to calculate it. 

## Solution

We can use this python script to calculate the value of our magic number. 

```python
p=29674495668685510550154174642905332730771991799853043350995075531276838753171770199594238596428121188033664754218345562493168782883
N=p*(313*(p-1)+1)*(353*(p-1)+1)
print(N)
```

Now all we need to do is start the challenge instance, run our small calculation script, and pipe its output over to `nc`:

```bash
python3 calc.py | nc IP PORT
```

Just like magic, out pops our flag. 