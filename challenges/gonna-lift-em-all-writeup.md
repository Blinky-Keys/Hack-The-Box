# Gonna-Lift-Em-All Writeup

Quick, there's a new custom Pokemon in the bush called "The Custom Pokemon". Can you find out what its weakness is and capture it?

Gonna-Lift-Em-All is a very easy difficulty challenge from Hack The Box. To solve it, we need solve some modular arithmetic equations to recover the flag. 

## Files Provided

- `chall.py` - the script used to encrypt the flag
- `out.txt` - the output of `chall.py`

## Challenge Script

```python
from Crypto.Util.number import bytes_to_long, getPrime
import random 

FLAG = b'HTB{??????????????????????????????}'

def gen_params():
	p = getPrime(1024)
	g = random.randint(2, p-2)
	x = random.randint(2, p-2)
	h = pow(g, x, p)
	return (p, g, h), x

def encrypt(pubkey):
	p, g, h = pubkey
	m = bytes_to_long(FLAG)
	y = random.randint(2, p-2)
	s = pow(h, y, p)
	return (g * y % p, m * s % p)

def main():
	pubkey, _ = gen_params()
	c1, c2 = encrypt(pubkey)

	with open('out.txt', 'w') as f:
		f.write(
			f'p = {pubkey[0]}\ng = {pubkey[1]}\nh = {pubkey[2]}\n(c1, c2) = ({c1}, {c2})\n'
		)
if __name__ == "__main__":
	main()
```

My first observation is that the script appears to be using an encryption technique similar to RSA as it is using modular exponentiation to encrypt the flag (though this script isn't *actually* using RSA). 

We're given quite a few variables for this challenge. Inside `out.txt`, we get the following variables:

- `p`
- `g`
- `h`
- `c1`
- `c2`

We can see that the flag (`m`) is being encrypted with the following code:

```python
m * s % p
```

The result of this is being stored inside the variable `c2`. We can reverse the effects of the above equation by multiplying the result (`c2`) by the *modular multiplicative inverse* of `s`. Unfortunately for us, we don't know what `s` is. 

Looking at the script some more, we can see that `s` is being calculated like so:

```python
s = pow(h, y, p)
```

We've been given `p` and `h` already, so we just need to know what `y` is to work out `s`. But we don't know what `y` is either. 

Notice that at the end of the `encrypt` function, we can see `y` being used in the equation that is used to return the first ciphertext `c1`:

```python
g * y % p
```

We can calculate the value of `y` by finding the modular multiplicative inverse of `g`, and rearranging the above equation to isolate `y` (with $x$ representing the MMI of `g`):

$$y = (g*y)*x \bmod p$$

$$y = (c1)*x \bmod p$$

## Inverse of `g`

There are a couple of ways to work out the modular multiplicative inverse of `g`. It can be calculated either using the Extended Euclidean Algorithm, or by using the built-in `pow` function that comes with python (or your language equivalent, assuming you also perform a modulo operation after calculating the exponential). 

### EEA

There is a python library that will do most of the heavy lifting if using the EEA is desired. You can find more information about it [here](https://pypi.org/project/egcd/). 

The `egcd` function will return a tuple with the following values for some inputs `b` and `n`:

- GCD of inputs `b` and `n`
- Coefficients of Bezout's identity (`a` and `m`), which satisfy the equation: 

$$ab + mn = gcd(b,n)$$

The coefficient `a` will be our MMI for `b`

```python
from egcd import egcd

# modular multiplicative inverse of b
bMMI = egcd(b,n)[1]
```

### Power Function

Using the python power function will only return the MMI:

```python
# g = number for which to find the modular multiplicative inverse
# p = the modulus
x = pow(g,-1,p)
```

## Calculating `y`

Once we have the MMI of `g`, we can work out `y`, use that to work out `s`, and then finally work out `m`. 

$x$ represents the MMI of `g` for the following two equations:

$$y = (g*y)*x \bmod p$$

$$y = (c1)*x \bmod p$$

$x$ is reused to represent the MMI of `s` for the following equations:

$$s = h^y \bmod p$$

$$m = (s*m)*x \bmod p$$

$$m = (c2)*x \bmod p$$

## Solution

Putting it all together, I produced the following script to decrypt the flag. 

```python
from Crypto.Util.number import long_to_bytes

c1=83194887666722435308945316429939841668109985194860518882743309895332330525232854733374220834562004665371728589040849388337869965962272329974327341953512030547150987478914221697662859702721549751949905379177524490596978865458493461926865553151329446008396048857775620413257603550197735539508582063967332954541
c2=46980139827823872709797876525359718565495105542826335055296195898993549717497706297570900140303523646691120660896057591142474133027314700072754720423416473219145616105901315902667461002549138134613137623172629251106773324834864521095329972962212429468236356687505826351839310216384806147074454773818037349470

p=163924920994230253637901818188432016168244271739612329857589126113342762280179217681751572174802922903476854156324228497960403054780444742311082033470378692771947296079573091561798164949003989592245623978327019668789826246878280613414312438425787726549209707561194579292492350868953301012702750092281807657719
g=97407673851268146184804267386115296213106535602908738837573109808033224187746927894605766365039669844761355888387043653015559933298433068597707383843814893442087063136640943475006105673619942401850890433169719970841218851182254280222787630139143746993351533776324254770080289574521452767936507196421481076841
h=7771801879117000288817915415260102060832587957130098985489551063161695391373720317596178655146834967333192201720460001561670355858493084613455139466487717364432242890680666229302181326080340061384604634749443972114930849979067572441792867514664636574923631540074373758015873624100768698622048136552173788916

x=pow(g,-1,p)
y=(c1*x)%p

s=pow(h,y,p)
x=pow(s,-1,p)

m=(c2*x)%p

print(long_to_bytes(m).decode('UTF-8'))
```