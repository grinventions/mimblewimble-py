[![Build Status](https://travis-ci.com/grinventions/mimblewimble-py.svg?branch=main)](https://travis-ci.com/grinventions/mimblewimble-py)

# Mimblewimble in Python

We are building the first Python-based implementation of the Mimblewimble protocol for the [grin cryptocurrency](https://grin.mw/). At the moment it is at the most early stage of development. Heavily based on the [grin++ wallet](https://github.com/GrinPlusPlus/GrinPlusPlus).

## Usage

### Generating wallets

Simplest operation is simply make a new wallet

```python
from mimblewimble.wallet import Wallet

# instantiate the wallet
w = Wallet.initialize()

# derive the slatepack address and the recovery phrase
path = 'm/0/1/0'
slatepack_address = w.getSlatepackAddress(path=path)
recovery_phrase = w.getSeedPhrase()

# display  the output
print('Your slatepack address at the path {0} is'.format(path))
print(slatepack_address)
print()
print('Your recovery phrase is')
print(recovery_phrase)
```

it will respond

```
Your slatepack address at the path m/0/1/0 is
grin14xfltfnzfq68mc6k7xru469h2x0ejckzr7alczcjf2wml755qnuq8c0zkx

Your recovery phrase is
mammal scale present develop then tail identify movie pizza brisk entry regret match solve coffee empower double muffin curious virtual joy hen diagram vacuum
```

### Restoring wallet from the recovery phrase

You may restore the wallet from the recovery phrase as follows

```python
from mimblewimble.wallet import Wallet

# content of the core wallet encrypted seed file
recovery_phrase = 'sign interest obtain raw window monster jump bring nice crunch toward grunt prosper recycle sphere battle mother fold reject velvet emotion similar romance govern'

# instantiate the wallet
w = Wallet.fromSeedPhrase(recovery_phrase)

# derive the slatepack address and the recovery phrase
path = 'm/0/1/0'
slatepack_address = w.getSlatepackAddress(path=path)

# display  the output
print('Your slatepack address at the path {0} is'.format(path))
print(slatepack_address)
```

it will respond

```
Your slatepack address at the path m/0/1/0 is
grin14kgku7l5x6te3arast3p59zk4rteznq2ug6kmmypf2d6z8md76eqg3su35
```

### Restoring wallet from the encrypted seed

Fully compatible with seed generated by the core wallet

```python
from mimblewimble.wallet import Wallet

# content of the core wallet encrypted seed file
seed = {
    'encrypted_seed': '839773da8062af7dc51714fd98a7f9a72750e17aa54541d5317b5ea1be5c5751db85497aa630380dd984e2ecd603ae0b',
    'salt': '356f045acf2b2787',
    'nonce': 'b5a490e1c942e6a5147bb740'
}

# convert to bytes
encrypted_seed = bytes.fromhex(seed['encrypted_seed'])
nonce = bytes.fromhex(seed['nonce'])
salt = bytes.fromhex(seed['salt'])

# don't forget your password
password = 'grinventions'

# instantiate the wallet
w = Wallet(encrypted_seed=encrypted_seed, nonce=nonce, salt=salt)

# decrypt
w.unshieldWallet(password, nonce=nonce, salt=salt)

# derive the slatepack address and the recovery phrase
path = 'm/0/1/0'
slatepack_address = w.getSlatepackAddress(path=path)
recovery_phrase = w.getSeedPhrase()

# display  the output
print('Your slatepack address at the path {0} is'.format(path))
print(slatepack_address)
print()
print('Your recovery phrase is')
print(recovery_phrase)
```

it will respond

```
grin14kgku7l5x6te3arast3p59zk4rteznq2ug6kmmypf2d6z8md76eqg3su35

Your recovery phrase is
sign interest obtain raw window monster jump bring nice crunch toward grunt prosper recycle sphere battle mother fold reject velvet emotion similar romance govern
```

### Detecting invalid password

While the master seed is being encrypted, the MAC tag digest will be verified indicating if password was correct.

```python
from mimblewimble.wallet import Wallet

# content of the core wallet encrypted seed file
seed = {
    'encrypted_seed': '839773da8062af7dc51714fd98a7f9a72750e17aa54541d5317b5ea1be5c5751db85497aa630380dd984e2ecd603ae0b',
    'salt': '356f045acf2b2787',
    'nonce': 'b5a490e1c942e6a5147bb740'
}

# convert to bytes
encrypted_seed = bytes.fromhex(seed['encrypted_seed'])
nonce = bytes.fromhex(seed['nonce'])
salt = bytes.fromhex(seed['salt'])

# don't forget your invalid password
password = 'Lt. Col. Frank Slade'

# instantiate the wallet
w = Wallet(encrypted_seed=encrypted_seed, nonce=nonce, salt=salt)

# decrypt
valid = True
try:
    w.unshieldWallet(password, nonce=nonce, salt=salt)
except Exception as e:
    if str(e) == 'MAC check failed':
        valid = False
if valid:
    print('Password correct!')
else:
    print('Password invalid!')
```

it will indicate failure of verification of the MAC tag

```
Password invalid!
```

### Building coinbase

```python
from mimblewimble.wallet import Wallet

# instantiate the wallet
w = Wallet.initialize()

# pick path and amount
coinbase_path = 'm/0/1/0'
coinbase_amount = 60

kernel, output, path = w.createCoinbase(amount, path=path)

# display  the output
print('Kernel')
print(kernel.toJSON())
print('Output')
print(output.toJSON())
```

it will output something like

```
Kernel
{'features': {}, 'excess': '0927759d4f4fc554e148f1906166381b6c1889895c6f96c3e2e76c55c9e219848b', 'excess_sig': ''}
Output
{'features': 1, 'commit': '098dcf471cf019030c82044cee5e794b0e31d11e00567920d8e5a40103eb63071f', 'proof': '00000000000002a352184e4a3f6dc6c75b447c3228a3202ac1c8a54d259a8441c89aea9b8bc6d9c820f71e8a5a567266e985071ea585cbee1808add28949695f416041d979685d4608b011d3594cc2437f1dff7d37653110f44328d8f7238cd414cbd314d424cbaa14b75e5df5dfb6f7627c0cf88516fea9a6c9f4a78702adf04f973027364ff5ff1c266115f6426230d268ee0437b17db66c769afce8f4af169d8a4394382fddc20ec4f6db705fc8f0c62cf27b28b965c0865609b7570d61a490a702ebef7e47f5b0c0150b88b276dd7aa34b273fe03972ae56d6bf9ca2e08a9dc13b556ff39ab1a6e756b49258e7a98c09e545e404cc676f891172d06844525ac709af135f4ff96d33d24522fd2274b49a955fe733069e45057e6b7a6cbd5f6afe8aa532b33bbbead86932d5563e4197da22077aa7c1271e09412ce6cd7e5be6ea7e52e335a50e34eea38f05bf389690c2a10c6313b9de376bcc95c5a306c4e4b418a0484fa7c124260019558b9b0507cdfcdbaeead4f51e1c727ec08ae4d8855b0a81b00afa03f48d0c484ed7ed0226a5f39076a31dd2369724d870d227b0e7f0822ac2eb1add54c6e3a37dd62dbf4cf6b6890f9881852a40c6a849ffaa1172aa941a0a9fb34f110e5d9f0695d058f4fe6a1b5202758c520e77f318e47fbd2eaed55d4320e0fb9c0b0cbdfaaed051c24c1bfa7aa565ff5df81ca434e03d392df1da255a7e877ec2d4cf8cec0f366bf3fa45738900d92c4e330e9ae586306c5b03f9d65068f884927a8102337f95ae6be17a72975b9d0ba134f41ef9c331d8e8da1fb1d30e8f722e8e9bc2a789f532c04529cdb31332bd5cb21d4d3a8ccd66b2635a797e930df87389a6b67d71a525d6ed5b57a413fa29e558d8ece38a09b69350943a5e681eedbfbe907b4b0e9ae9a0daa470d500866a2cda57a2840c959b2f4992e1573d2b91c25186'}
```

## Expected features

* Managing blocks
* Managing transactions

## Use-cases

* Implement python-based wallets and nodes for [grin](https://grin.mw/)
* [Research](https://forum.grin.mw/c/research/11) new protocols, quickly drafting ideas and testing them
* Have [grin](https://grin.mw/) codebase that anyone can easily understand and translate to other languages

## Useful docs

1. Regarding serialization/deserialization [p2p protocol document](https://github.com/mimblewimble/docs/wiki/P2P-Protocol#compactblockbody)

## Tools

1. [Python's BIP32](https://pypi.org/project/bip32/)

## Support

This project is NOT financed from the grin fund neither grin community fund. I deliverately did not request funding because of the following reasons:

1. I am not certain how much time I will be able to dedicate to it
2. I want this project to earn trust from the community, not have it guaranteed upfront

Anyone who wishes to support this project is welcome to donate to the following grin address

```
grin1vcjsgk6rltncqh7cxjywukjfrf825d8a6xk77msfuhf9ev3r55wq7l2ng4
```

which is my donation address, my username is [@marekyggdrasil](https://github.com/marekyggdrasil) and if you want to know more about on the [grin forum](https://forum.grin.mw/) I am known as [@renzokuken](https://forum.grin.mw/u/renzokuken/summary) me check [my website](https://mareknarozniak.com/).
