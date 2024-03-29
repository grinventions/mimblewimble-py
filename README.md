[![Build Status](https://travis-ci.com/grinventions/mimblewimble-py.svg?branch=main)](https://travis-ci.com/grinventions/mimblewimble-py)

# Mimblewimble in Python

![mimblewimble-py logo](https://github.com/grinventions/mimblewimble-py/blob/main/assets/logo.png?raw=true)

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

kernel, output = w.createCoinbase(coinbase_amount, path=coinbase_path)

# display  the output
print('Kernel')
print(kernel.toJSON())
print('Output')
print(output.output.toJSON())
```

it will output something like

```
Kernel
{'features': {}, 'excess': '0927759d4f4fc554e148f1906166381b6c1889895c6f96c3e2e76c55c9e219848b', 'excess_sig': ''}
Output
{'features': 1, 'commit': '098dcf471cf019030c82044cee5e794b0e31d11e00567920d8e5a40103eb63071f', 'proof': '00000000000002a352184e4a3f6dc6c75b447c3228a3202ac1c8a54d259a8441c89aea9b8bc6d9c820f71e8a5a567266e985071ea585cbee1808add28949695f416041d979685d4608b011d3594cc2437f1dff7d37653110f44328d8f7238cd414cbd314d424cbaa14b75e5df5dfb6f7627c0cf88516fea9a6c9f4a78702adf04f973027364ff5ff1c266115f6426230d268ee0437b17db66c769afce8f4af169d8a4394382fddc20ec4f6db705fc8f0c62cf27b28b965c0865609b7570d61a490a702ebef7e47f5b0c0150b88b276dd7aa34b273fe03972ae56d6bf9ca2e08a9dc13b556ff39ab1a6e756b49258e7a98c09e545e404cc676f891172d06844525ac709af135f4ff96d33d24522fd2274b49a955fe733069e45057e6b7a6cbd5f6afe8aa532b33bbbead86932d5563e4197da22077aa7c1271e09412ce6cd7e5be6ea7e52e335a50e34eea38f05bf389690c2a10c6313b9de376bcc95c5a306c4e4b418a0484fa7c124260019558b9b0507cdfcdbaeead4f51e1c727ec08ae4d8855b0a81b00afa03f48d0c484ed7ed0226a5f39076a31dd2369724d870d227b0e7f0822ac2eb1add54c6e3a37dd62dbf4cf6b6890f9881852a40c6a849ffaa1172aa941a0a9fb34f110e5d9f0695d058f4fe6a1b5202758c520e77f318e47fbd2eaed55d4320e0fb9c0b0cbdfaaed051c24c1bfa7aa565ff5df81ca434e03d392df1da255a7e877ec2d4cf8cec0f366bf3fa45738900d92c4e330e9ae586306c5b03f9d65068f884927a8102337f95ae6be17a72975b9d0ba134f41ef9c331d8e8da1fb1d30e8f722e8e9bc2a789f532c04529cdb31332bd5cb21d4d3a8ccd66b2635a797e930df87389a6b67d71a525d6ed5b57a413fa29e558d8ece38a09b69350943a5e681eedbfbe907b4b0e9ae9a0daa470d500866a2cda57a2840c959b2f4992e1573d2b91c25186'}
```

### SRS transaction building

```python
from mimblewimble.wallet import Wallet

# instantiate two wallets wallet
alice_path = 'm/0/1/0'
alice_wallet = Wallet.initialize()
alice_address = alice_wallet.getSlatepackAddress()

bob_path = 'm/0/1/0'
bob_wallet = Wallet.initialize()
bob_address = bob_wallet.getSlatepackAddress()

print('Alice: ', alice_address)
print('Bob:   ', bob_address)

# Alice makes 60 coins coinbase output
coinbase_amount = 60000000000
kernel, output = alice_wallet.createCoinbase(
    coinbase_amount, path=alice_path)

# attempts to send 30 coins to Bob
num_change_outputs = 1
amount = 30000000000
fee_base = 7000000
block_height = 99999
send_slate, secret_key, secret_nonce = alice_wallet.send(
    [output], num_change_outputs, amount, fee_base, block_height,
    path=alice_path, receiver_address=bob_address)

print()
print('send slate from Alice')
print(send_slate.toJSON())

# build the receive slate using Bob's wallet
receive_slate = bob_wallet.receive(send_slate)

print()
print('receive slate from Bob')
print(receive_slate.toJSON())

# finalize the receive slate using Alice's wallet
finalized_slate = alice_wallet.finalize(
    receive_slate, secret_key, secret_nonce, path=alice_path)

print()
print('finalized slate that Alice has')
print(finalized_slate.toJSON())
```

expect output of the form

```
Alice:  grin1rn9jvtzlffsk4dht29nqtw8ja65r749jvmcm3833kadt76dajr4qra9e6m
Bob:    grin18gxjdmmq53fpx9330atjqs8x3tc7jw6dcthe043pzrr9d2nletqsnt3pu9

send slate from Alice
{'amt': 30000000000, 'sta': 'S1', 'off': 'a18fa6bfd76257149e449bd8bd816a4ce3de8af539a794f937c1d39dc78b771e', 'fee': 322000000, 'coms': [{'c': '09ea9b319f2bbf94eb21f8e996e42fb2c2968e939bf18e8acdbd4192546df16296', 'f': 1}, {'c': '09e17a9b2eed70ef1438a449f9c89eb7a795a71c3e0f398bf5f13b6c8a814aaac0', 'p': '00000000000002a320a4e80ea09225153b9230859f1e0c3a637501efbbde25c6fd6ef01ae62294164b437a8b895b9db7ebe9081c49fb26a7d69cd3c40a0609b28c78b4e7637c7523044d81198c3044bbedb4f069086bdfc14530740290efe51be45c2bad65500993f88c6ab3273d40633a6a51aebdb150b3b33ebeb8b19e46524949aeb4af246e44e80a326af52e22e952a4c23a285bd3c3ad5aae325c3f891ade0b4630bf55bbde56c8a53dc571e7b59863b7f689027466784af112509900bf821f8830d061b2ffa2812d47122e8e7dc3f0be6b596121f3a858bf9a69c658787776f6af691bd817c5f31d2910a11e4d7737b2247b1a64eb4a5f6d5083ead8eb2e9706bde1c5463ecc7042be326554dea8e2db20d28f4e6c41550ff9c463ded09d034e9d82324fbe4592bac6f69e3eaf22291b0fbd74faba1fe194881cfe8ba3997213ce3ec8011a7d984742480b1464b4d88e074ebb4a68b0a529941819a6da3a2fe9efaed11890cb63007166751da04e00ebd3110ac8b8084f75505df1617681154a9530f117c59661e8e5533595058ff0fc202035f9aa19493195b96682b5a357a18faee8139c52365c5a42b9f4ee2ac964a2861dd7a88a8a5a58be86eb46e1c76ae30d3e681532117162ea084e41a7aca289373f8008e1a558620ec1d67d639d0480900927c725422593ae7f2ff2d554317c9fca496ce955fd784bc93c124a95415bd3c47011449bf88635e6492a5b9bada3ef970cfd5941f56f5aa82aa044aa314623bc4bcea8d4e90e56c0d403d934d8b321244fdf2ba31ba853a039281a19882eb5fdcbdd2ac8861bd8570971d81a5ff5bf4c293c821174c5f220a887e5a559c116a7c1afe2b2d5081a177e327a1d161af226be8e95f6dd8098b52c989f72920001ca1deb676f50330da8f0a7685b85c31644399b4c8351ac1d7febca3382c64a19d8e4a39af59f'}], 'proof': {'saddr': '1ccb262c5f4a616ab6eb516605b8f2eea83f54b266f1b89e31b75abf69bd90ea', 'raddr': None, 'rsig': None}}

receive slate from Bob
{'amt': 30000000000, 'sta': 'S2', 'off': '84b02f977be855ca2a748362aa535da833a4bb7786ac7263e880f1d9b00ac3fb', 'fee': 322000000, 'coms': [{'c': '09ea9b319f2bbf94eb21f8e996e42fb2c2968e939bf18e8acdbd4192546df16296', 'f': 1}, {'c': '09e17a9b2eed70ef1438a449f9c89eb7a795a71c3e0f398bf5f13b6c8a814aaac0', 'p': '00000000000002a320a4e80ea09225153b9230859f1e0c3a637501efbbde25c6fd6ef01ae62294164b437a8b895b9db7ebe9081c49fb26a7d69cd3c40a0609b28c78b4e7637c7523044d81198c3044bbedb4f069086bdfc14530740290efe51be45c2bad65500993f88c6ab3273d40633a6a51aebdb150b3b33ebeb8b19e46524949aeb4af246e44e80a326af52e22e952a4c23a285bd3c3ad5aae325c3f891ade0b4630bf55bbde56c8a53dc571e7b59863b7f689027466784af112509900bf821f8830d061b2ffa2812d47122e8e7dc3f0be6b596121f3a858bf9a69c658787776f6af691bd817c5f31d2910a11e4d7737b2247b1a64eb4a5f6d5083ead8eb2e9706bde1c5463ecc7042be326554dea8e2db20d28f4e6c41550ff9c463ded09d034e9d82324fbe4592bac6f69e3eaf22291b0fbd74faba1fe194881cfe8ba3997213ce3ec8011a7d984742480b1464b4d88e074ebb4a68b0a529941819a6da3a2fe9efaed11890cb63007166751da04e00ebd3110ac8b8084f75505df1617681154a9530f117c59661e8e5533595058ff0fc202035f9aa19493195b96682b5a357a18faee8139c52365c5a42b9f4ee2ac964a2861dd7a88a8a5a58be86eb46e1c76ae30d3e681532117162ea084e41a7aca289373f8008e1a558620ec1d67d639d0480900927c725422593ae7f2ff2d554317c9fca496ce955fd784bc93c124a95415bd3c47011449bf88635e6492a5b9bada3ef970cfd5941f56f5aa82aa044aa314623bc4bcea8d4e90e56c0d403d934d8b321244fdf2ba31ba853a039281a19882eb5fdcbdd2ac8861bd8570971d81a5ff5bf4c293c821174c5f220a887e5a559c116a7c1afe2b2d5081a177e327a1d161af226be8e95f6dd8098b52c989f72920001ca1deb676f50330da8f0a7685b85c31644399b4c8351ac1d7febca3382c64a19d8e4a39af59f'}, {'c': '092540d07c1dde2de274ac14f0e42d6e542851c3e7bbb0987b19354b9999800aa1', 'p': '00000000000002a3beaced67b4c66ff1d446fa3413cc8caa8ca717e0456d77eb57631d7e5a10995a35c81008965ace1c29e5b9e7535f4320d907699a1ebfe005c33106a1c90e89c701f96cb8a7c5c72b421db1a3b189979bfe042293f0582e9d7aa6520c0a95d9df98a0f75e6adf914bb3b9a8bf34fbddeae0f6b8e64c9bdf1bcf0aad51dbb7cb34ce3fca3057f16fdd6d10d9980f6360e5d99f358daf17ef5689d565d1bc64ae9ac21ead036a5f6602be3a274fe6c16ace3ce467839a6bdd0d8006d47ea67d0a5df8b178e7de1baeb13e95fbfae9b8b71bb8914427376e31c843d642143ac41f682acb92b30f32f5ae426daab93a2a2e60d5b5326fa830f65bcfb7dbbc71c8b59866830c2a739e3eaec6339994cd42ce13cf6400e29e7c7251f67b605e356e3bf3d9d27f73b0f361e09fdef9c51f065b1c3b0d9d6afe782d7c00d321fa034620d24643149ac2e2c3d499df4c3487ec39885102d286a7f07f4e5fd4c70788f9f24147eb02a4b0e486fd3b22dcd09eccb0efe6e1a7e90089ce5afd27d67d32ba68d8cd3a906eaacda55d1792081c372bd0f695a94cad62b07c817ff3328e3dbbe0bf832139fac3d04016fb7f6cb77de9ba22435c74d28ad4c340e2593eb01280a55e80f31b633a96009239e512f66415ddc06c4e85e0d26c0bbe2c33b4e97010ec69ea2e95b0f388f5529f57ad96d37f45da06f7f43ead8ad71fb48da3a1a028c24c410094420b1651ecd233f344ea3cc51d7cb84f91c33c3993d39199987965d7c6f1f26969cc35486bea243ce9f5084423443580e9252155f17a21742919fd3e379fe31abd173939b15ef181c37e8b68f13fa45f8d513f0d0475306c12cfa5d7871ecb794347413088fc91cdefd0553188e9a1d2b9a464d82b95867af81cf76fc56e0a1eddf82550c0a6b30a3eac462abcc78c287e8e66b1cd6950cf36c8ef68e6df3d1b'}], 'proof': {'saddr': '1ccb262c5f4a616ab6eb516605b8f2eea83f54b266f1b89e31b75abf69bd90ea', 'raddr': '3a0d26ef60a4521316317f572040e68af1e93b4dc2ef97d62110c656aa7fcac1', 'rsig': '35392393ba925f976c9fee85424489a9d6116f1a1a4547d133056a39215714902d172a1ea8b3271929fdf6ae981ae7ec264095fd98300f9ced73be50644f500d00000006fc23ac0008aae8f9a55ebbc33f5b13ba1c9eadd4218a514360c4d9c10be9c9b681e8d86ccb1ccb262c5f4a616ab6eb516605b8f2eea83f54b266f1b89e31b75abf69bd90ea'}}

finalized slate that Alice has
{'amt': 30000000000, 'sta': 'S3', 'off': '84b02f977be855ca2a748362aa535da833a4bb7786ac7263e880f1d9b00ac3fb', 'fee': 322000000, 'coms': [{'c': '09ea9b319f2bbf94eb21f8e996e42fb2c2968e939bf18e8acdbd4192546df16296', 'f': 1}, {'c': '09e17a9b2eed70ef1438a449f9c89eb7a795a71c3e0f398bf5f13b6c8a814aaac0', 'p': '00000000000002a320a4e80ea09225153b9230859f1e0c3a637501efbbde25c6fd6ef01ae62294164b437a8b895b9db7ebe9081c49fb26a7d69cd3c40a0609b28c78b4e7637c7523044d81198c3044bbedb4f069086bdfc14530740290efe51be45c2bad65500993f88c6ab3273d40633a6a51aebdb150b3b33ebeb8b19e46524949aeb4af246e44e80a326af52e22e952a4c23a285bd3c3ad5aae325c3f891ade0b4630bf55bbde56c8a53dc571e7b59863b7f689027466784af112509900bf821f8830d061b2ffa2812d47122e8e7dc3f0be6b596121f3a858bf9a69c658787776f6af691bd817c5f31d2910a11e4d7737b2247b1a64eb4a5f6d5083ead8eb2e9706bde1c5463ecc7042be326554dea8e2db20d28f4e6c41550ff9c463ded09d034e9d82324fbe4592bac6f69e3eaf22291b0fbd74faba1fe194881cfe8ba3997213ce3ec8011a7d984742480b1464b4d88e074ebb4a68b0a529941819a6da3a2fe9efaed11890cb63007166751da04e00ebd3110ac8b8084f75505df1617681154a9530f117c59661e8e5533595058ff0fc202035f9aa19493195b96682b5a357a18faee8139c52365c5a42b9f4ee2ac964a2861dd7a88a8a5a58be86eb46e1c76ae30d3e681532117162ea084e41a7aca289373f8008e1a558620ec1d67d639d0480900927c725422593ae7f2ff2d554317c9fca496ce955fd784bc93c124a95415bd3c47011449bf88635e6492a5b9bada3ef970cfd5941f56f5aa82aa044aa314623bc4bcea8d4e90e56c0d403d934d8b321244fdf2ba31ba853a039281a19882eb5fdcbdd2ac8861bd8570971d81a5ff5bf4c293c821174c5f220a887e5a559c116a7c1afe2b2d5081a177e327a1d161af226be8e95f6dd8098b52c989f72920001ca1deb676f50330da8f0a7685b85c31644399b4c8351ac1d7febca3382c64a19d8e4a39af59f'}, {'c': '092540d07c1dde2de274ac14f0e42d6e542851c3e7bbb0987b19354b9999800aa1', 'p': '00000000000002a3beaced67b4c66ff1d446fa3413cc8caa8ca717e0456d77eb57631d7e5a10995a35c81008965ace1c29e5b9e7535f4320d907699a1ebfe005c33106a1c90e89c701f96cb8a7c5c72b421db1a3b189979bfe042293f0582e9d7aa6520c0a95d9df98a0f75e6adf914bb3b9a8bf34fbddeae0f6b8e64c9bdf1bcf0aad51dbb7cb34ce3fca3057f16fdd6d10d9980f6360e5d99f358daf17ef5689d565d1bc64ae9ac21ead036a5f6602be3a274fe6c16ace3ce467839a6bdd0d8006d47ea67d0a5df8b178e7de1baeb13e95fbfae9b8b71bb8914427376e31c843d642143ac41f682acb92b30f32f5ae426daab93a2a2e60d5b5326fa830f65bcfb7dbbc71c8b59866830c2a739e3eaec6339994cd42ce13cf6400e29e7c7251f67b605e356e3bf3d9d27f73b0f361e09fdef9c51f065b1c3b0d9d6afe782d7c00d321fa034620d24643149ac2e2c3d499df4c3487ec39885102d286a7f07f4e5fd4c70788f9f24147eb02a4b0e486fd3b22dcd09eccb0efe6e1a7e90089ce5afd27d67d32ba68d8cd3a906eaacda55d1792081c372bd0f695a94cad62b07c817ff3328e3dbbe0bf832139fac3d04016fb7f6cb77de9ba22435c74d28ad4c340e2593eb01280a55e80f31b633a96009239e512f66415ddc06c4e85e0d26c0bbe2c33b4e97010ec69ea2e95b0f388f5529f57ad96d37f45da06f7f43ead8ad71fb48da3a1a028c24c410094420b1651ecd233f344ea3cc51d7cb84f91c33c3993d39199987965d7c6f1f26969cc35486bea243ce9f5084423443580e9252155f17a21742919fd3e379fe31abd173939b15ef181c37e8b68f13fa45f8d513f0d0475306c12cfa5d7871ecb794347413088fc91cdefd0553188e9a1d2b9a464d82b95867af81cf76fc56e0a1eddf82550c0a6b30a3eac462abcc78c287e8e66b1cd6950cf36c8ef68e6df3d1b'}], 'proof': {'saddr': '1ccb262c5f4a616ab6eb516605b8f2eea83f54b266f1b89e31b75abf69bd90ea', 'raddr': '3a0d26ef60a4521316317f572040e68af1e93b4dc2ef97d62110c656aa7fcac1', 'rsig': '35392393ba925f976c9fee85424489a9d6116f1a1a4547d133056a39215714902d172a1ea8b3271929fdf6ae981ae7ec264095fd98300f9ced73be50644f500d00000006fc23ac0008aae8f9a55ebbc33f5b13ba1c9eadd4218a514360c4d9c10be9c9b681e8d86ccb1ccb262c5f4a616ab6eb516605b8f2eea83f54b266f1b89e31b75abf69bd90ea'}}
```

### Deriving TOR addresses

You may use `mimblewimble-py` to convert grin address to .onion address, which is useful in checking if wallet is reachable.

```python
from mimblewimble.helpers.tor import TorAddress
from mimblewimble.keychain import KeyChain

slatepack_address = 'grin1m3ckuft0llw97ulzmedk557twyn76wkgxartn6lpfq5xd9wcc24qnpwde5'

# ed25519 public key from slatepack address
ed25519_pk = KeyChain.slatepackAddressToED25519PublicKey(slatepack_address)

# ed25519 public key to .onion address
onion_address = TorAddress(ed25519_pk).toOnion()

assert onion_address == '3ryw4jlp77of647c3znwuu6loet62owig5dlt27bjaugnfoyykvneayd.onion'

# you can also validate the .onion address
# it will check if ed25519 public key is a valid curve point
# and also if checksum is correct, only V3 TOR addresses are supported!
TorAddress.parse(onion_address)

print(slatepack_address)
print(onion_address)
```

outputs

```
grin1m3ckuft0llw97ulzmedk557twyn76wkgxartn6lpfq5xd9wcc24qnpwde5
3ryw4jlp77of647c3znwuu6loet62owig5dlt27bjaugnfoyykvneayd.onion
```

you may use TOR proxy to reach foreign API listener under `3ryw4jlp77of647c3znwuu6loet62owig5dlt27bjaugnfoyykvneayd.onion` to check if wallet is listening.

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
