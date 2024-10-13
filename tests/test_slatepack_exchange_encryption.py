from mimblewimble.models.slatepack.message import SlatepackMessage, EMode
from mimblewimble.wallet import Wallet

address_a = 'grin14kgku7l5x6te3arast3p59zk4rteznq2ug6kmmypf2d6z8md76eqg3su35'
address_b = 'grin1m4krnajw792zxfyldu79jssh0d3kzjtwpdn2wy7fysrfw4ej0waskurq76'

seed_a = 'sign interest obtain raw window monster jump bring nice crunch toward grunt prosper recycle sphere battle mother fold reject velvet emotion similar romance govern'
seed_b = 'rough spy shallow parade boil sausage toss year used senior infant hen impulse prefer divorce flame drink save tackle front record scrub march doctor'

ba_s1 = '''
BEGINSLATEPACK. auBNnRrahGnJ1iw 52RSppvCNzAPyT8 p5icMiMDYjDKbHH
8gd9Xci3AWGMd88 PWt36uc7uPVKocB SnxB28ptvgmfEn3 SouRUUBnjSEQCGi
gkwuzswEKLict2X A7sc7Rdu21gMFec Eq5AmyExTCjPHYg CU1DWQZC28kab8y
Fu1meQA5sYUQWM7 rvg1yADen6Z8R4S b3eVPg54eYwNv17 XqV1Lc3ACLSHycK
Gc7dPmAmBeZ7RxY JLdteR1QtFu8ngu GHSTNrui3TVkKug QJuN34WsJcCZWFc
AYKSYdBnwdXSPYy LsPCS3n4Mqo52HP U8kCq7sHsBdBbjV 9dcFQrm18pvWxVR
GJNm8XSrQtK9dyQ JvZxjv7UNTvh8q1 5yDXLA7z8L6NV2m dHZ6ujtecsSZdF5
mZqZyjsxeoj9kDr jjAXPD6gTVjobkh sjxXb1YU4qEfHnR wx7NjBx5RamzgEa
uWvARddnJd8pG2m wsptfQkvfBKogS5 1vRvmFMUb8MwPjW hucAnKcMaFLj1Hg
ESbV3HycopcL2VJ HJgmQQeFsqbyGMm Xkiz4sH2X6hWj1A D6rkR7uhDLL5YbY
MPwkFsRNK8zcPk7 X2DMCFZd5VNGcMZ gPBidMhw4nbUzii bj42vtLpT68JpTM
qeLUsuCzBUPs7h5 Z8vH9humdjkxkPM JK2z91cLcyWpqfN PCK2C96aWRmw1zK
vhA2bdauCkTRDD4 dES9RdcExqtMjby p2wvUFk2V2UHEw7 Sjpcc37kJ2P2ZG2
WYyM3VSXuMPSdwZ HVyvnXs4tSJTzsE 2wJTS5gRJX74FXW izjtA8tUGWcmCif
kBYie74pEWBAe4t ja5SLKkX4Ut1Ys8 rwPyB5zf6sGzrb7 3VyDtX85AmF7moE
MbaYHdP1tbM. ENDSLATEPACK.
'''

ba_s2 = '''
BEGINSLATEPACK. 8eeCbUNBQbXjjEa 9FMu2nM18wKWmgn Ychgtt7UqXkMnUk
7Y7NyvUqKqjXWj9 4xYUi1RwrqqKhqU c3xGHjGFDuFATDG LiqhJr3XJ453Qar
TrLgsU3juNeQto8 UfqHeNcjBM3obcu uUqnJH7UH1eRoV7 ehWLPQk5DQYWmMe
vsTqKABAo37U5Di uDUz6W7HCJvfWnW DJvHCTxqCPaTRwk WJMZx2AH9qdyaHw
PRtpoC11F7Cjxa8 HWb63pXRC5ieJVA LkZhXrA8jFb3S5k uuNvZKjetBLXJS2
8JDhAShCmQmM5kC Vyq3cAHi79yx5xq mAy3wRB4H7EogUU G1ih3MZx48YgrzA
sVcA68KgC5TLcLX 9EncMNbx7WbAwte prkNQZaL7JRCzt9 v1qsRBphS43d3kE
vuYsazrj15uSyuP sbn5LfjEEdXtTop AZ9ioi4XAkSohLx ytFbYpC7KSEwZsu
ijE7GY35RwVmhGa mAHUafWCy7Nk3NG GG2gxxG1uqejaYn Tx7qAm8VyFzQAsc
iWcALGmFu9g33Lu 2QkRfxhYjfqhrUA jhEzxrB2bzArsHG xpEh8S6ZrfS5e36
mZ6k6ZP71nwjre4 q18kGby8uw8o7bN Gc3chEYgyzBE3DE BvGWabEtE2Zpj8s
gG2Wj3Tg36YZBhv mP6CMGswgo2ZGSw ykBTeMbw57muTED wSUjeoJNfkK1thc
w6wCjwL4F6tzoWC NCHRc5esngfnoDs vLt6PMY3qHds3vu hYqte8jRsf2biHG
LrgFDbZ39NKYNeg LhrJctCHpee4Rye 3rGQK17KC7m3atV 7S926vmWp4LQVfZ
R8KbeZzEXkqjP4a FgntJUqVX7CJeAG r3cnrCyLsum4zEA gjRWiDtLZwXSypo
LuWrAu9oAYvHzK5 KQcK9H6GLho2Eus cJp3tqduRTmx97r 16PT6ZJ2PSQVyFW
egs3t4DEb4sKc6K bKBdw3MvnDeJTye yzgJtBiDpsGE4Tp F6NJbemA5bJfoPG
VNFeRYwm1hdHuTF p3chUTpMzr7EHZf q19MNQx1rhdzjnP wW2sN1ShsRHX9qu
owfwxmd8dTpSAXn hM6xujAWMonTNKT 1YL5AL28xeAJYpT a2uqFKaVx5y9D8M
cDK5pcY7wX8r2jc 9JXXoUKQ98JZLSW 7fGeFCAe7MrtPR1 t64FPwgYHgFkpd7
WrmJkfwWFShmcz4 1cb6aw93PZncen7 BLNyhAb9D99cd5g JjKGKyDnfMNjP4F
J7UWPR95cUsBoyX YToqZVn4evsG5vk sBsEaibznofuo6A WYGRVpNszPggEYH
UuEkbKHkyZdwoiP HdPyEVEz7mcrRQF sb1RTbiBYLy7syz hMCoaDBFBkHMGVw
vUFkfzdZ866USCP CQtRxKdmTbY6sSJ xwqnsRpKTXEmtSx 7oysfbY6zC9Rnfr
8WS1bUsqjaFZj4j fCFR2UD3iYDP5Kq 3xfeYLosZaAtouN 17pPv4X39zPpGGc
QeYHpgPEB581aJy CYRvmBdkuFuK4pY rLrnwpdNa5ugijM BLcozDYrHEV2WHU
nNfv6fAvjkB2Z3m dsji1im3mL2yJdy zcp4BVcG7WN3XDt m8D1GUSEocfaxTm
9JmmXGhAJuARz21 fqYpxs6HngxZAqd oiEKmFYqcACewnG TT55WR8wFsSV4wf
cwAYPmPX99G4SS1 heohousAXMwLxmG F4JBAKbsgKJUQTu jqiZfkhEzLCcZH2
fbFEjdVmZkVVMMq GzPg6Xt2ttXYBFh PwfkwCmH5tBvjXg pJDpVhybnbzXxSZ
E2itVArrj6MSYyN svFEmac817qZfjH NyVeq8DCuo2ScPw bBY7JhXh6j4pzeZ
sLGhvaFtVaARrsz 71eprF7HV9AjhLH jhpRruGeAgMxtpB C12JKLSXXqiBABT
UqRdwmMQTnDJKCz 7w5utNFyFbc335z kQzR8jvdPFSP1i. ENDSLATEPACK.
'''

ba_s3 = '''
BEGINSLATEPACK. 4a2nUgAKEK8d2Az ZdgMA1nwgiSn2th MpyxW1z1nwqZpma
ZBekrEDmSdz8e7s ekpGSBv9qtnL4vN yhLqpcwcSFuJoNt 2vdFzB3RCmas4qJ
UGnZ25D8qtZXEtN MDSUCv86cVkbeTv DMfU32mCEGNriP3 jmAhdUZZcXTMxXE
EXDUC3xpHUX4Fd2 FgvvGrwCPAoXzDr Yt5rzqhp4F4MmiE CJcPMAaWdx5LeqN
i1YBdQVf5Pr645G nojmue85VZrKtEs zR3guVVV2huqxXZ PUAdN6KLNswwaYC
VoTLVvEvmyrHQAu S33w5NG7wVYndpk Sn1u4XTZtftaryz QY2LWRNGvShz2we
RWKPWugDmtDftuj rvKbF8qAwWcRfu9 EoZnAiJQoEj1bJj TomGvdKCnEngzup
fmx4h5z7vcSSUVH nTN3S3FDU1Tosoc QjCHNp6Zn6wMRtj EWZT72CHLNP9aTK
EV6K6WGVo8QDPoJ FtifVaiu52T9T83 tzoR6VRVnPSdrXH EyTMBxxKQSSHbvH
SwDu4M37rC7ic5H 2i89sjnGunHJzHt wvAQQm7FToS53Fi UeMsnccPHeedwbs
h6TPnbznT5ZzyUE zH4fxH94mveCGHh 9X5W8DHNpWcqohS kw3yJBnDkvvuoec
QSstz1uWUGfA1Zh mq4cRnBJAjXQaqP 6aDL3XxmYo4oFrL 4rxeQZokPMwZKvc
3dZp9DqMGiQtZVH Qqqeik1M9SMjRnZ 924FMfrjgHTKabd Nbp1DMDHp9fbhmk
NykX81th5ntK9Jv 4P4XyPcbUUFWiFL hcBN2woqtH63Wwa m3PndM2oTTtpCZk
NZE1EymDXhdNBTW 7CyR8gZF52Cjw1K Tk4BNGefTJmzohd GyVg12RuqJUU9aS
cTyUEygg92HCA73 pKXas4rvYXeXh9v pdYWSLghjoSTUap 49Uh72TkDViU4bq
GqnYYMwFVEW5SFN xjiXk3JYgB9cqC1 PBWbNUvJyWuaP3b rFR3cdA2aRxYzbF
MynkiSaYpiXUTEB mt7DC1heGwGB8Re xUpRMwsUtAziUVy 2PrhKtHpECzLAv7
cV8cFYURoDhWCbJ ZyqaENGVtBbauhR jCUVX6qzG4BCBAM nVtgnjBPdz7peGn
WBeXGbistzuFJv7 y41RzPGG71VAfZP hSZ5i8HU4L9KQWi 41f1zuKFdW5qaVZ
mzAsAYHEbtWuLNk CHBNPdbHqBirATA BhwzozweqzwJxj5 FA2wYS5LostE7hq
Y1gHcjLxa2kWPsi ELKNuGxW2pLemKo oYK1aJbpMhVPJaQ GCFvSr56Xejy5Ec
KxKnLBniBFkP7KF 2ZfZ7kF6xjELUdy afkN2cTssWNbfpo fNjBMCkf6jFWXyg
duXPYVJK9KD9U8W wfH1fQpE7zZPohK vonJsgoaFvFc4VT Rp1DgSPELmXAHYZ
gAsvxEyZfFdgFbM iApmLSYwuN8FzsF TqXbTeT9BwAb7i5 FD3s1nRZNpii3y4
YsFUpkZq9WgSz91 Mj8WsnKSh5j2dLq 7Paj5mMC7TUA4a7 zfYB2HQChuATizJ
c5X2yA9pVgQGUTf Dshw65T4jpMoU3e jGVBGMWaXBnyX4Y qdDNfLxcnDAHgUC
5geNtGMMft9ieXL kpxdMXkZ33wjGpe EmikWq46SjpyntA 5NWs4jYCArbFrFU
XhEyiQbn1zmze9j fGWttMcsoPkaHkc 881Vzx1srFsV6h4 siDGJugfFKucX5i
cfdvmHbvx5Sf5Kn cfGmTi6CnQJNT6y 8aSaWdUo8XGrsz. ENDSLATEPACK.
'''

ab_s1 = '''
BEGINSLATEPACK. AHPuvBgs9jCYy5E KAfMU8gTZGFtsPy y9qicNQpkNaiXko
evHryZXtdcuzAnP Jzwkktz2ErCbG9b 8BR6VqLvczzHYWG L6tdBEE1GjqssUH
foRSrRiSoHmimH2 EUisvcn9zb375xx 1b7WNZSYTNgDvfm rmwxeyNE4Q2pVaM
HXi1BzvLj2njAU1 dUxqrT6Fnqkju6P 6RnCNu7UwySae4N RTeUQuyCjv1tZhp
epoFTv9LWn5VtsZ 6xBRVG23AapSWav mr38mS6f3hTB3Ac 9aYbnaFjrBK6jc8
F4a8zvUEfN7gbK1 vC81aVFRUJRzRcz ZSvgzW6DZnJ9tfp jwiTkUNUC9BrtNG
BMx72z6sEKC61jQ RCNMYMLVyFkgc38 iokxKVmLYzVHn9m qJGVUNHitSHo5kP
gvojLmyAvxwFngV ri9BBA9Uqui5ZQz nqSJUzrUv5nYmVj br8Z8nvG4XWLydZ
WZxuWUHFG2Rxhnm iiRpFC1sVhTx2cZ j1QSpzsNror43j1 8vqa3neimQyQu4p
i9DHkAVb7xAKxTy Nh5mt9GcsoR5sTC iqHhKQUowhX6577 nDJpvfueRh8VJuK
EfLjZwhbQR4K2He 5bruawb22wxVHxQ T1fwrDHuz4qptN5 Q8yhmcxbsNL2gEp
piS9m7pfupVEeDc aJKr5YKPk8WcYn5 6CjV6z2XXi7pKDj PCXzrhRzHCqLjBK
N2epP35N1cAnBxm 1cA9Kc3NG5TMVBg bpwYsKQXvFHheGe vMox2WM8WEZY8bT
jqsAKHS. ENDSLATEPACK.
'''

ab_s2 = '''
BEGINSLATEPACK. CE8TL6eVNw1ukDc wgV1EEF5gfgMJhx HiWwgYnKV5xFfdF
fwFPVzzwtqTKqoV wZSgMSc1nVnVYZB D1ZKCYPwHSAA3R3 oNeX4qzhKbJtJUL
vpr8sQ2oJEzXDCk GheGQC9Z3bZ7R56 KDdH2tym4g5L9mi HoagXZPryELYn4E
7ym7YLKZj3oxLU5 bvn9WPVzyPeXL8g mt2YrAZBJ6dJW2y YeQHTHrVSquK2ov
s2G7FFhoCLzbKJd LprxppZCaV6TAdE 8Qbuttb45MeWuKs YsqiaTaQUWK4mSV
ARdvUQ9RdzNgeok topuyehfxZ2u2t2 CW6HemB53vs8Dg8 wtASFn7zsVjh6PC
LXrSN6g3e81KykY Vva2mU7zUWUBoef QFnNpUAGY4Ez7pW PvCHduh1oXxmFCv
7SLH7jpLEqUCc3A zNTDHKTRgXj9VpU Puyakzd7zhKT3jS JbU1ukZp3vm7jwz
vV2hahQQQjnyLkx hLB9LjcwjdPpWBL eMfj4i4xo1vtNLu xCHPYJhWDXDfdj3
k6zRqPtAQKCtke9 8zjnaLiuub2gB1F XgGjrwdZzBzw6eX TCHxgCdKaECnLeS
1NwSsKmwks8cyr7 NbVtWvnckwN1tzS 5PUdMMuWLYRdmrH LZsX1mA9kEEftcj
dhKMuV2eivid5Jx xAo8zFb9NQxEmK6 ESqsfcTrP7r96oV iwwMEvafBFLsH7h
p5VRwxLMLoAqSBg FTawaq8x2RNiHNV NNvzC15VX22G7Cv v3KP3YHsEi4ubiC
fjzKoUhA8sDno4G tKe2nY7UckBj4Ur WZWKjbVXfPTggVK k8i4YtFo4tMM36b
5AgbHZqU66tzyeq j2Y7Nei7NGMf1Lo nCEBWjBFPD3vcW4 5U4gCe7skhZN2AT
tMpeJz2me6RDvTy JJm8bJZbg8i8Ghg 2PtmJJ6sqBodx4s uxvLEgjKo3DbY2M
9QjFu2Zw4Vrm17W ww4rbdQfBiby4MZ ZMQSorVBnsTjHeL wifrbjwyhHtxHX6
VXFVKk2Cwv6K3qZ p3zu7bdyifHeMti UBgGmePBYbky2K2 nyPmRy3nTM1JV5L
dG5pG84JH4Ux3Cv eTMCX38Ah1Q8kjn 876phh1aDH5HX8u UX2GCcwBUABJdCC
W8CTCPRQ6Gq6FGd 5eWNAJ5aZUT63k7 1U6tyBegJiWvVyj rqnfWBEzd1CAwrJ
vzkyoNYWZouZjL3 p56u3nHUfu4fYg3 31rQ3UtLhxDRFq1 5z4oLhFEnEX6vo2
h72Za9ErqGWYTGd f3UgcpnNPoqFwP2 X31j6EPxBYEwgzT dD5fCuHF1bWb5bX
Z5v6UUKSE249WzA bjEBeB1jiZ15qY4 dYeL3hBzB5hSxsx 4dVBc7mi9kBg62c
1bAqoRdR8jkQGAR P5QVwSCC15kpQCG SjRq6wR6DdiuAij NyPHHGDxWDK873T
TRX7pCfum8eLFry 9GJVfZe21pzdDF5 V7oFWL3rVHNoK6Z PJy5VNvKXSkX9fp
o7CKo5bQZ2MBEAV DVKSWZ2RcEcutZw NuLAbSyyLBANR5J dWXZ9fyS9tThcZy
tcEPaUc1VqWHoSx YQ5bd4ijdrgQa1Y SNKCUotRg8tJhCd Pr84rZ6BfEjNtK8
VgZazaxqjwWDbuk uLc5gR32yUJhJ4B NvoZ1EkeABgrGhY K5CyCRCEwhvqxUv
iwrSKwm984aAdQ2 2TvfJ56PHuUYWvr ua1WuCQd548ZX62 9FVRxew29XBoMcy
Lu2xmgXtifuV8qH C5E44j4MGfPEc7k ZTp3YnP1SwHJ1Pg 7UHzorq93pQxSPs
bpctSssfjoVjGnb GHNnTNyMtgRBHXQ 3ycqFPQsohdmQqs Yc174wN3twFGyFU
vorm3ueYN1DZ69r Z12gXBJ5Z4ezh1X arSrW6X5muNkqBZ tKUexx3QRwzaerU
DD3aBesCS3fgVvB WggqQavB1bVXQyb anDbFfN5hrEQ7s9 LxFNipBVN9jmbZV
YAcDHDpA. ENDSLATEPACK.
'''

ab_s3 = '''
BEGINSLATEPACK. 6mgFQ6Xw82pHsaQ FCe3ikRVJpvQwbs kAgMTpRdRjzR1K8
9uKBmG9Re13gy6T pTLNhUTibVo9wZW BEwJ5K1E8ujzSNV 8Kd2FSBef4u72xd
qQHc7gU2Vmc6wJs sDt91xfDB929rcB C8kcYZX2csuxXJu cKW28svofnadW7F
fedv6LYFcsP1FBA ZTDk6GjCz8GxpXq rrPNMpKUaUn1zAj 6KsLRY7PfHtRKLS
U53LzNqmMPsJK7M mEPSdpcjPx3pC81 vnToHA9TnzUtiku jfFztnxNh5icdZM
UWgSdaLPnKUFuHd jZeyEHSVdbAK6gV 8QGtEsJ96yi4pZT 2rKNA63xK3MqrFS
eT1umnVN58AgPpq sURaQxBUHzsS9t3 RNbjtEwiNDWVrTQ CEADif1eVtGc1do
y3C6ELg4Wb9qMa3 zRZ3cWJTLWpg72P 1879hXrCTVyxg4i kLVBGi3sWzyrL8S
uVVp5kHQ2tapsWi fvju1V1JxGMrNnR f5ae1gtDCniAoBc KweezcJaGWSJxT5
Ldoo5kDvgh2cJTa gGfJ7tKW7qzsKMA wnerNjmytXKuhAc BWkuA6dVy5yJb7y
RYhjGb9nt3Dsxkv ffxCMiKSvMLxSLq rpkKcsxoTpYDTEr Hzmr7z28EJyWCXp
DfQs1KHaMaR7Vjy krtSbGQKpw8NoUz UuQwrtSeBU7NNhi 2eKvKSXS1kG1uwz
Y4aDgVYGXvbJwvK n5e1GbVH2Cu8qhH DoAyHVCBXC6LVU2 Xws67RD17y8QKBt
BKsNDFCAdHWbS6z KbdBpWH5aSWWeTe ShfD6qm1riUCjmE feHcbEPT1KA3ZJV
4ZomRxKjExCFcYB CfSU2aTXMVyczEx FjLHT59nySUViLm MzkDkxA55G8URmh
NhEVz1BwoYHQzdM F49ntkGJQw55Wnu z9Hd54NrBDSVCWT H7S34SukJvWyDF8
FEMNv3bvZyBJL9j FbQmwyJi6inso6T f3KspAQFYP5rAH5 QXAgMHAF3g1eJP8
2KEoCr25N8ujW6J BBzHcjPZXp5AeXJ VtZHaAstrzvb28m QpvrLsYwQEqrt7E
ryd2ffU4unZ3EG4 PkguaPSwhx1qCBY tcbUGkQx1Az1HRR oVCfc8HR1N4QAko
67Tve1XfvJQM5aT 3pYHCJXA7RbEq8i 1ikHhBZBS9idU5A EaVESetd4fPuxxa
7MRaz6dtq8XG9Lo XD7ADiZ5yB7EAbL L64gRyT85zdBasT YnzkP2EhsMx67Vy
RjysYwPid2wmbxP W1dTqRqZrG3Qj7j xkHg1jvCLqb4WNx qDMMKbzqcxiwHHM
8ngkUv451mtn5aG RtgiFqiYzgZNR9z TBYLiHoH6zRGn4r ye3uUPsxVxDsuZT
J9ZehQZ2dvzu17M 5JKSuXrXTiCzrms 583UvAvzx22jaUy P2f6ZvsPLraBZJK
1vodaEecLJHag8q FGaqLrBPNXwRcot EFXpFP5qNSVjRtV iRhHEbrKAbFmMmr
zSKjWkD17AQGJQ7 Nof1hK3cCyKFPxg Qb3RFFFJoBfXR8j H6ENFYs5t9bFZMd
4GPThSf6tbNyaRL TzFZVAHtwM6qFY5 VKXQtpb7anRGPLS F9zDrvsfHQJJ6p1
2c9ysqf4CMtzV6Z tWecYj9rYRnkaaH 9UQRe4q8DLa6VP9 5hP2ngNRJ32EYp4
aYkfvy1vL6myHRU troRtT6xR18d2dh GKHfxnNafYwvRZZ g7nojM1rR93JM1W
HPdFpjmHmEEvFQh 5cnjKCooj4SCfVG UcisyT3rJbAdaG. ENDSLATEPACK.
'''


def test_slatepack_manual_decryption():
    # prepare wallets
    w_alice = Wallet.fromSeedPhrase(seed_a)

    # manual way tutorial
    unpacked = SlatepackMessage.unpack(ba_s1)
    s = SlatepackMessage.deserialize(unpacked)

    assert s.toJSON() == {
        'slatepack': [1, 0],
        'mode': 1,
        'payload': 'YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBGL0gzaGY2M0hycTJNSCtPMW5hV202K004MTg0dTNTN29lSFE0VkhpTXpZCnBiVWNMTEhkVDVQR24vb1llaUQrdHNVTzFvZXh1clNabVNWdThIY3Y3bWMKLT4gRXNbLWdyZWFzZSApdksxZUMgbFZ4dVNgLDYKU2ttZ3lDREcwd1BiMHd2R2VZcDZYYmRTeU1PTmZYWW9SUEx5UVNsa3NlOHREeGtUSEt3am96NlkzdDJJSXFIdgpVL2R4eVcyaVp5WjFVVkZScmxOQVZiWGJFQndxaHBhRmpEZFJjaXZoYkRvMXVUTDVDRE52Sno4OXcraXZhb1VjCgotLS0gbnEwaEp2L2JWM2tMUnJxS1U5d2xrZXhGMlNUWkRtQmYwaGxlZXMvSHlXdwqMQcMrGq8Qk1QYD/lKFK+wzXe5EKeQPlYtwz1Er3dj3m8I73jdGYVEdEetyIgqhOVaB0eVCK3KuIFOGkr8l3qo/FLYWaSQzFsFmDmxndFV3HNKdcfEuZEDBwhD1fs+c4AiCYUpjCgdTJ+i6q7yZvh+/sjIFN5LRNiLMtLK9L1Nz+hfiAMkPeERKDVn3pxGLFPsMCMqLqDmSA+UiwLR2XbquHUlRHC0uYhKdnq5Bx4kD/WA5bzlSYufyOEE7DBUmfFjQ9WQsjcYHYidheoHEcSSDAfuxbgf8ibyOQBS1La/ZRj93RqP8MMk/DDz3GDt0L2qvQmd8ZMupqZDDws7nnJ+UL3h1fUf2j595UqTyN70Xp+9u2xL8+NoUO/csr0F8Qie4JauZ9kbx/IvuL4lYVnfxlQ='
    }

    if s.is_encrypted():
        encrypted_payload = s.getPayload()
        decrypted_payload = w_alice.ageDecrypt(
            encrypted_payload, path='m/0/1/0')
        s.setPayload(decrypted_payload, EMode.PLAINTEXT)

    assert s.toJSON() == {
        'slatepack': [1, 0],
        'mode': 0,
        'payload': 'AAQAA1P+Bc0Hi0uPlgtWr28aM7EBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAADrcDeAAAAAAAL68IAEAAlMz9n6EXttW4wnWnBvFa4lU3gmCuizkIRMLchUZp6eaAjLZtJkEPfs1zpdSOzmmDRsiyi6XMmJwS3Wz1h4F1JbpAt1sOfZO8VQjJJ9vPFlCF3tjYUluC2anE8kkBpdXMnu7rZFue/Q2l5j0fYLiGhRWqNeRTAriNW3sgUqboR9t9rIA',
        'sender': 'grin1m4krnajw792zxfyldu79jssh0d3kzjtwpdn2wy7fysrfw4ej0waskurq76'
    }

def test_slatepack_exchange_encryption():
    # prepare wallets
    w_alice = Wallet.fromSeedPhrase(seed_a)
    assert w_alice.getSlatepackAddress(path='m/0/1/0') == address_a

    w_bob = Wallet.fromSeedPhrase(seed_b.replace('\n', ''))
    assert w_bob.getSlatepackAddress(path='m/0/1/0') == address_b

    # Alice decrypts ba_s1 slatepack
    encrypted_slate_message = SlatepackMessage.unarmor(ba_s1)
    assert encrypted_slate_message.is_encrypted()
    assert encrypted_slate_message.toJSON() == {
        'slatepack': [1, 0],
        'mode': 1,
        'payload': 'YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBGL0gzaGY2M0hycTJNSCtPMW5hV202K004MTg0dTNTN29lSFE0VkhpTXpZCnBiVWNMTEhkVDVQR24vb1llaUQrdHNVTzFvZXh1clNabVNWdThIY3Y3bWMKLT4gRXNbLWdyZWFzZSApdksxZUMgbFZ4dVNgLDYKU2ttZ3lDREcwd1BiMHd2R2VZcDZYYmRTeU1PTmZYWW9SUEx5UVNsa3NlOHREeGtUSEt3am96NlkzdDJJSXFIdgpVL2R4eVcyaVp5WjFVVkZScmxOQVZiWGJFQndxaHBhRmpEZFJjaXZoYkRvMXVUTDVDRE52Sno4OXcraXZhb1VjCgotLS0gbnEwaEp2L2JWM2tMUnJxS1U5d2xrZXhGMlNUWkRtQmYwaGxlZXMvSHlXdwqMQcMrGq8Qk1QYD/lKFK+wzXe5EKeQPlYtwz1Er3dj3m8I73jdGYVEdEetyIgqhOVaB0eVCK3KuIFOGkr8l3qo/FLYWaSQzFsFmDmxndFV3HNKdcfEuZEDBwhD1fs+c4AiCYUpjCgdTJ+i6q7yZvh+/sjIFN5LRNiLMtLK9L1Nz+hfiAMkPeERKDVn3pxGLFPsMCMqLqDmSA+UiwLR2XbquHUlRHC0uYhKdnq5Bx4kD/WA5bzlSYufyOEE7DBUmfFjQ9WQsjcYHYidheoHEcSSDAfuxbgf8ibyOQBS1La/ZRj93RqP8MMk/DDz3GDt0L2qvQmd8ZMupqZDDws7nnJ+UL3h1fUf2j595UqTyN70Xp+9u2xL8+NoUO/csr0F8Qie4JauZ9kbx/IvuL4lYVnfxlQ='
    }

    decrypted_slate_message = w_alice.decryptSlatepack(ba_s1, path='m/0/1/0')

    assert decrypted_slate_message.toJSON() == {
        'slatepack': [1, 0],
        'mode': 0,
        'payload': 'AAQAA1P+Bc0Hi0uPlgtWr28aM7EBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAADrcDeAAAAAAAL68IAEAAlMz9n6EXttW4wnWnBvFa4lU3gmCuizkIRMLchUZp6eaAjLZtJkEPfs1zpdSOzmmDRsiyi6XMmJwS3Wz1h4F1JbpAt1sOfZO8VQjJJ9vPFlCF3tjYUluC2anE8kkBpdXMnu7rZFue/Q2l5j0fYLiGhRWqNeRTAriNW3sgUqboR9t9rIA',
        'sender': 'grin1m4krnajw792zxfyldu79jssh0d3kzjtwpdn2wy7fysrfw4ej0waskurq76'
    }

    assert decrypted_slate_message.getSlate().toJSON() == {
        'ver': '4:3',
        'id': '53fe05cd-078b-4b8f-960b-56af6f1a33b1',
        'sta': 'S1',
        'amt': 987500000,
        'fee': 12500000,
        'sigs': [
            {
                'xs': '025333f67e845edb56e309d69c1bc56b8954de0982ba2ce421130b721519a7a79a',
                'nonce': '0232d9b499043dfb35ce97523b39a60d1b22ca2e973262704b75b3d61e05d496e9'
            }
        ],
        'proof': {
            'saddr': 'dd6c39f64ef15423249f6f3c5942177b6361496e0b66a713c924069757327bbb',
            'raddr': 'ad916e7bf4369798f47d82e21a1456a8d7914c0ae2356dec814a9ba11f6df6b2'
        }
    }

    # Bob decrypts ba_s2 slatepack
    encrypted_slate_message = SlatepackMessage.unarmor(ba_s2)
    assert encrypted_slate_message.is_encrypted()
    assert encrypted_slate_message.toJSON() == {
        'slatepack': [1, 0],
        'mode': 1,
        'payload': 'YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBmbVFzbFlUeURuK3R1SUd3WmtiYk9PTUd0djY3c3lrWVYzaXd0OUh6UjNnCkp6eDFhR1YvZ1orN2FkRDdHWmRqN2JsN3RlNTFYVUZINVZJMzM2RWI3SUEKLT4gOCZoMkNLLWdyZWFzZSBVSiFQaDQwPwpYZUlJWkdNV3QraDBmQ3pXR0RUVnUvM29Kc2N2WWoxbGRFNmhlSnEwa0MxbmhMOGhBd1Z3bVhQbFdjcGNPais5CjBMdVRPMTRDCi0tLSBrdFE1YUpvLzBhaWNYcGh0dGw3YmpTK0t5ejVQbllYd1lZRjJqeVFsUjJ3CjBzNyM8pnZbCELsjLt2MrUUxJG7Fm665i/y24utTxzsPzdzhBpVash8Kgxys5e1XtBYJEOqcWmoxX0BZg1BAKezfqT5rNJ3NEhju0J029gZ3oKYd9tYE2ly5r3ZtiXOyEsvwJ8oxA7GN+UuQ5TYnLgDZnV4QVUv+Ho/vOXoqNFkc7a4J3PgtpNg3EGeB0rlMHkwMkKneNMPm/IrdGhnREe8mUMPR9tFRZiYsuVnQ65Yuuc2R3OrJ0Sw45wTxMCnt3MtazX5MC0s10wUXqz5xbwvi86t7mJhZdoeC0aGZt/Zy/lh05sPfQyWndHF8HPzdBWfxavjOGK1vPcuwynzfGj7klpMuqwixMiR8svuJ9ITY9NdJMWHVtH7DplOMybUEVYIAzJ8qp8721VflHo9PAP3Mpd896z5JM9tlPPnCbql+ZvEdW3x/eC604vUyijTMc/ODOdW9u8Kyn4vfstFkh5godmWCtZeQ5lMpcZb3EKdZs4/1AcYQM5uhZyBAI9ugbF/Yvo42xVlDUMV733cyD44rlnOPwd9ZnGjUOwoiOm7Knz6saNc4hm1k07AkERhYLVirpznVkIrVt3IEzDpPbPUsdD0T8vKcSBsDJgb3S7XmlXPIocn9jDmH64PBfh6KJlE+Smfzd/1NOX94km6YMxMQJJ4gptGRp99bNTBCVaXUX6qPxf57pE00hrr8mVYdSD+dZUX3CTqCPmjxS3mKjVYzBA3w9tqCoS1Ynamcv9XgHGQ16hbymuLBbP0PrD+f07TiCYUaeQeVkiAZ0lcPDXtGA1zsjkBEANAST1+wsXLzYuUkGGQHbbsrWGY/DKfp36vkr2fM2TuFadLHdQPOaV/RqYmbW+NE1pyzhNaHw6xsrlvmQV2irnsleA+N7sOkweN3H0RQDQOdCiD7HEnAr7kxsEpUnk+nsgiLQuBf6sbL4OQ2BAxqjZvfQdlCgPSh0UvrcK2FHJvdzzh6YvaDSttvQgzljypHhO18dfp+S3ely33IqAOQuo+5deoejMafEBWaCIVU0jPIHPAFzYc9b+itcHeqYiXpBpaVVcOBscSRL+CG48PsV19GLPpQj1SLqN5E+8IquIGlhYvWsFB2IU4CJrLHF6Ohk1g2jT6bVf2YS/C77XWYWalJAoAadyW1SaaNRfQ8/WzDFoHa2PNV+Kg5VRnhfD7i53eq+WJedXBOSnhP2b1VYHGnmYBHngiTOwzuWl3ehvJyVO9d9YXYYdlKp197KjUo3igbUoswvmLNVycT1UhZyeFN6h36fzoCJvy0N04j6ScF9ndbuBauvnzWUYv7SkNp+X+twSQXdIIlAaPEHTlw67AlEgQ75nkCOJfnBDO+Cd9fVaECdYMT5n3QvYEm2vORaXlDgwPYtY+xoJqbe5zCY3HduZ1N6+0tE1kObfUOysXwf6DWBh3nec4m4tHNgYpYhTF4GCjXlXX9zComLKIkitb8kGxzRBM+AsErw6S9vvpr3zPInLr/htx6s5Pst5dJM9DoYjN/QZV50k='
    }

    decrypted_slate_message = w_bob.decryptSlatepack(ba_s2, path='m/0/1/0')

    assert decrypted_slate_message.toJSON() == {
        'slatepack': [1, 0],
        'mode': 0,
        'payload': 'AAQAA1P+Bc0Hi0uPlgtWr28aM7ECQEiMwcqE4OJ0v4WrC58Sq8wYoIyD6f6jFCWrA2uMo48AAQEDCwq0jluOoUy+IeAG4DY/sUmpIHl9DUgGDfUNhsxDAisD+9oFyODFaa5IRF+Xq/+7L0wrdnlq5Xtk4O8Nb5cHAaL72gXI4MVprkhEX5er/7svTCt2eWrle2Tg7w1vlwcBoig1KMskAAB69AIK+2MBdSWpSIcw6220+mMa+lajJUzyAwABAQAJb/ypAPNhBVfE9Qc+zBiClBWBE6qIFhVWIYP18samsmoAAAAAAAACo2RHJ5usYpRb4hEPP+srfIlzRPMrJVyBsPerZMy9Vxfy1SCnJaojLzXUT/rbWh7/01u8Z+j+lTLfLFCWgePCne4AUmgXcz6qjPBZ9D75gOgnjQ4vptkyh4iBunGycMOT4arXJjf4ZpBPq+O+Ri+8tix1Fc71vXvJMILMpZ+OhUCWQ6IcLKHni0o5ENqHt0iZueY/LYqfD+benJ/T7ZA3gLphasWLU4DRscsKUNi/SaJeb+Bs//VWmRwgwdLg/Q63TnQfMP0Pi++K7cbgd3mK9//2xqL8MvOHJeovC1iYn+4gsb036MebrBhe5gqg3BdxCEw9I0us3iU4ONGHj3f9y0Hxt/ZjtkPC2hfRwl9FptUGe7hMEkkV1faHL5+whZnbq9Tgkt3E6CRiuuXhDPk/wD12M1aBIfIvUKw53ELfmW4Sy04/JV0hfj6JYCPdLvbmYR4bCYJW+OGJOxJU74CBTLyT+gAzzJ9yp/VpllfJuNxXlwiEYFz03BqdtV8ZhhQmD88LAJRfF9pDTek1WNCDctl928aFYCY/xRNWxjtaG4FysyrMVNq380Rsp5WwDUCqRHdJshFPz+HnOZN31yo4aTSwQe49El59d7Tn03dYdtN3pU4BxmuJDuDR7prHryB6MSVVo7ABCnyACilmSvFmOp8y1vgCTbJXVrTj0MVARmv/O/yg5XA5CS59BnxKcAkKaTvCs6LZvXRb03kTNaDamycmvKzI23bCZTTDCwDBU1u9yB4+KLITF+pKx5TWr+6L91SSV585ClVwDVUV5zWkOZm1uSUGPI9fY0UnHN6yzwiKWCAtJdigaiV6FRBJfwz49fCeUCsu2OA1IUNQJ0dA4WKfZvyKhK2sgO3ny+sIHQG6U1LiSAmcpuVo/Ka2mpRAso8sM91sOfZO8VQjJJ9vPFlCF3tjYUluC2anE8kkBpdXMnu7rZFue/Q2l5j0fYLiGhRWqNeRTAriNW3sgUqboR9t9rIBjGWkBYvACKTsep3bSE9bV/9AHteumW4ldwZCx9hpTPCucZGwYDIDlonWPIrIPpWRHCUjRFERkvyF2AhsNJFECQ==',
        'sender': 'grin14kgku7l5x6te3arast3p59zk4rteznq2ug6kmmypf2d6z8md76eqg3su35'
    }

    assert decrypted_slate_message.getSlate().toJSON() == {
        'ver': '4:3',
        'id': '53fe05cd-078b-4b8f-960b-56af6f1a33b1',
        'sta': 'S2',
        'off': '40488cc1ca84e0e274bf85ab0b9f12abcc18a08c83e9fea31425ab036b8ca38f',
        'sigs': [
            {
                'xs': '030b0ab48e5b8ea14cbe21e006e0363fb149a920797d0d48060df50d86cc43022b',
                'nonce': '03fbda05c8e0c569ae48445f97abffbb2f4c2b76796ae57b64e0ef0d6f970701a2',
                'part': 'a20107976f0defe0647be56a79762b4c2fbbffab975f4448ae69c5e0c805dafbf24c25a356fa1a63fab46deb308748a925750163fb0a02f47a000024cb283528'
            }
        ],
        'coms': [
            {
                'c': '096ffca900f3610557c4f5073ecc188294158113aa881615562183f5f2c6a6b26a',
                'p': '6447279bac62945be2110f3feb2b7c897344f32b255c81b0f7ab64ccbd5717f2d520a725aa232f35d44ffadb5a1effd35bbc67e8fe9532df2c509681e3c29dee00526817733eaa8cf059f43ef980e8278d0e2fa6d932878881ba71b270c393e1aad72637f866904fabe3be462fbcb62c7515cef5bd7bc93082cca59f8e85409643a21c2ca1e78b4a3910da87b74899b9e63f2d8a9f0fe6de9c9fd3ed903780ba616ac58b5380d1b1cb0a50d8bf49a25e6fe06cfff556991c20c1d2e0fd0eb74e741f30fd0f8bef8aedc6e077798af7fff6c6a2fc32f38725ea2f0b58989fee20b1bd37e8c79bac185ee60aa0dc1771084c3d234bacde253838d1878f77fdcb41f1b7f663b643c2da17d1c25f45a6d5067bb84c124915d5f6872f9fb08599dbabd4e092ddc4e82462bae5e10cf93fc03d7633568121f22f50ac39dc42df996e12cb4e3f255d217e3e896023dd2ef6e6611e1b098256f8e1893b1254ef80814cbc93fa0033cc9f72a7f5699657c9b8dc57970884605cf4dc1a9db55f198614260fcf0b00945f17da434de93558d08372d97ddbc68560263fc51356c63b5a1b8172b32acc54dab7f3446ca795b00d40aa447749b2114fcfe1e7399377d72a386934b041ee3d125e7d77b4e7d3775876d377a54e01c66b890ee0d1ee9ac7af207a312555a3b0010a7c800a29664af1663a9f32d6f8024db25756b4e3d0c540466bff3bfca0e57039092e7d067c4a70090a693bc2b3a2d9bd745bd3791335a0da9b2726bcacc8db76c26534c30b00c1535bbdc81e3e28b21317ea4ac794d6afee8bf75492579f390a55700d5515e735a43999b5b925063c8f5f6345271cdeb2cf088a58202d25d8a06a257a1510497f0cf8f5f09e502b2ed8e035214350274740e1629f66fc8a84adac80ede7cbeb081d01ba5352e248099ca6e568fca6b69a9440b28f2c33'
            }
        ],
        'proof': {
            'saddr': 'dd6c39f64ef15423249f6f3c5942177b6361496e0b66a713c924069757327bbb',
            'raddr': 'ad916e7bf4369798f47d82e21a1456a8d7914c0ae2356dec814a9ba11f6df6b2',
            'rsig': '8c65a4058bc008a4ec7a9ddb484f5b57ff401ed7ae996e25770642c7d8694cf0ae7191b06032039689d63c8ac83e95911c252344511192fc85d8086c34914409'
        }
    }


    # Bob finalizes and makes the ba_s3 slatepack
    decrypted_slate_message = SlatepackMessage.unarmor(ba_s3)
    assert not decrypted_slate_message.is_encrypted()

    assert decrypted_slate_message.toJSON() == {
        'slatepack': [1, 0],
        'mode': 0,
        'sender': 'grin1m4krnajw792zxfyldu79jssh0d3kzjtwpdn2wy7fysrfw4ej0waskurq76',
        'payload': 'AAQAA1P+Bc0Hi0uPlgtWr28aM7EDIeyFsJzBL7KTpA+x8TNiWWuyP3prlZUI28ZAqFB2Xd4EAAAAAAC+vCACAQMLCrSOW46hTL4h4AbgNj+xSakgeX0NSAYN9Q2GzEMCKwP72gXI4MVprkhEX5er/7svTCt2eWrle2Tg7w1vlwcBovvaBcjgxWmuSERfl6v/uy9MK3Z5auV7ZODvDW+XBwGiKDUoyyQAAHr0Agr7YwF1JalIhzDrbbT6Yxr6VqMlTPIBAlMz9n6EXttW4wnWnBvFa4lU3gmCuizkIRMLchUZp6eaAjLZtJkEPfs1zpdSOzmmDRsiyi6XMmJwS3Wz1h4F1JbpMtm0mQQ9+zXOl1I7OaYNGyLKLpcyYnBLdbPWHgXUluk7wfBwJgPlSW7xw3ka1oM3q74mc3dyfy1+D9K2Vc1ynQMAAgAACCqQq7/DLLzi5Jbz46qzyBZx77KicvXZGGxUqttsj8OFAQAJb/ypAPNhBVfE9Qc+zBiClBWBE6qIFhVWIYP18samsmoAAAAAAAACo2RHJ5usYpRb4hEPP+srfIlzRPMrJVyBsPerZMy9Vxfy1SCnJaojLzXUT/rbWh7/01u8Z+j+lTLfLFCWgePCne4AUmgXcz6qjPBZ9D75gOgnjQ4vptkyh4iBunGycMOT4arXJjf4ZpBPq+O+Ri+8tix1Fc71vXvJMILMpZ+OhUCWQ6IcLKHni0o5ENqHt0iZueY/LYqfD+benJ/T7ZA3gLphasWLU4DRscsKUNi/SaJeb+Bs//VWmRwgwdLg/Q63TnQfMP0Pi++K7cbgd3mK9//2xqL8MvOHJeovC1iYn+4gsb036MebrBhe5gqg3BdxCEw9I0us3iU4ONGHj3f9y0Hxt/ZjtkPC2hfRwl9FptUGe7hMEkkV1faHL5+whZnbq9Tgkt3E6CRiuuXhDPk/wD12M1aBIfIvUKw53ELfmW4Sy04/JV0hfj6JYCPdLvbmYR4bCYJW+OGJOxJU74CBTLyT+gAzzJ9yp/VpllfJuNxXlwiEYFz03BqdtV8ZhhQmD88LAJRfF9pDTek1WNCDctl928aFYCY/xRNWxjtaG4FysyrMVNq380Rsp5WwDUCqRHdJshFPz+HnOZN31yo4aTSwQe49El59d7Tn03dYdtN3pU4BxmuJDuDR7prHryB6MSVVo7ABCnyACilmSvFmOp8y1vgCTbJXVrTj0MVARmv/O/yg5XA5CS59BnxKcAkKaTvCs6LZvXRb03kTNaDamycmvKzI23bCZTTDCwDBU1u9yB4+KLITF+pKx5TWr+6L91SSV585ClVwDVUV5zWkOZm1uSUGPI9fY0UnHN6yzwiKWCAtJdigaiV6FRBJfwz49fCeUCsu2OA1IUNQJ0dA4WKfZvyKhK2sgO3ny+sIHQG6U1LiSAmcpuVo/Ka2mpRAso8sM91sOfZO8VQjJJ9vPFlCF3tjYUluC2anE8kkBpdXMnu7rZFue/Q2l5j0fYLiGhRWqNeRTAriNW3sgUqboR9t9rIBjGWkBYvACKTsep3bSE9bV/9AHteumW4ldwZCx9hpTPCucZGwYDIDlonWPIrIPpWRHCUjRFERkvyF2AhsNJFECQ=='
    }

    assert decrypted_slate_message.getSlate().toJSON() == {
        'ver': '4:3',
        'id': '53fe05cd-078b-4b8f-960b-56af6f1a33b1',
        'sta': 'S3',
        'off': '21ec85b09cc12fb293a40fb1f13362596bb23f7a6b959508dbc640a850765dde',
        'fee': 12500000,
        'sigs': [
            {
                'xs': '030b0ab48e5b8ea14cbe21e006e0363fb149a920797d0d48060df50d86cc43022b',
                'nonce': '03fbda05c8e0c569ae48445f97abffbb2f4c2b76796ae57b64e0ef0d6f970701a2',
                'part': 'a20107976f0defe0647be56a79762b4c2fbbffab975f4448ae69c5e0c805dafbf24c25a356fa1a63fab46deb308748a925750163fb0a02f47a000024cb283528'
            },
            {
                'xs': '025333f67e845edb56e309d69c1bc56b8954de0982ba2ce421130b721519a7a79a',
                'nonce': '0232d9b499043dfb35ce97523b39a60d1b22ca2e973262704b75b3d61e05d496e9',
                'part': 'e996d4051ed6b3754b706232972eca221b0da6393b5297ce35fb3d0499b4d9329d72cd55b6d20f7e2d7f72777326beab3783d61a79c3f16e49e5032670f0c13b'
            }
        ],
        'coms': [
            {
                'c': '082a90abbfc32cbce2e496f3e3aab3c81671efb2a272f5d9186c54aadb6c8fc385'
            },
            {
                'c': '096ffca900f3610557c4f5073ecc188294158113aa881615562183f5f2c6a6b26a',
                'p': '6447279bac62945be2110f3feb2b7c897344f32b255c81b0f7ab64ccbd5717f2d520a725aa232f35d44ffadb5a1effd35bbc67e8fe9532df2c509681e3c29dee00526817733eaa8cf059f43ef980e8278d0e2fa6d932878881ba71b270c393e1aad72637f866904fabe3be462fbcb62c7515cef5bd7bc93082cca59f8e85409643a21c2ca1e78b4a3910da87b74899b9e63f2d8a9f0fe6de9c9fd3ed903780ba616ac58b5380d1b1cb0a50d8bf49a25e6fe06cfff556991c20c1d2e0fd0eb74e741f30fd0f8bef8aedc6e077798af7fff6c6a2fc32f38725ea2f0b58989fee20b1bd37e8c79bac185ee60aa0dc1771084c3d234bacde253838d1878f77fdcb41f1b7f663b643c2da17d1c25f45a6d5067bb84c124915d5f6872f9fb08599dbabd4e092ddc4e82462bae5e10cf93fc03d7633568121f22f50ac39dc42df996e12cb4e3f255d217e3e896023dd2ef6e6611e1b098256f8e1893b1254ef80814cbc93fa0033cc9f72a7f5699657c9b8dc57970884605cf4dc1a9db55f198614260fcf0b00945f17da434de93558d08372d97ddbc68560263fc51356c63b5a1b8172b32acc54dab7f3446ca795b00d40aa447749b2114fcfe1e7399377d72a386934b041ee3d125e7d77b4e7d3775876d377a54e01c66b890ee0d1ee9ac7af207a312555a3b0010a7c800a29664af1663a9f32d6f8024db25756b4e3d0c540466bff3bfca0e57039092e7d067c4a70090a693bc2b3a2d9bd745bd3791335a0da9b2726bcacc8db76c26534c30b00c1535bbdc81e3e28b21317ea4ac794d6afee8bf75492579f390a55700d5515e735a43999b5b925063c8f5f6345271cdeb2cf088a58202d25d8a06a257a1510497f0cf8f5f09e502b2ed8e035214350274740e1629f66fc8a84adac80ede7cbeb081d01ba5352e248099ca6e568fca6b69a9440b28f2c33'
            }
        ],
        'proof': {
            'saddr': 'dd6c39f64ef15423249f6f3c5942177b6361496e0b66a713c924069757327bbb',
            'raddr': 'ad916e7bf4369798f47d82e21a1456a8d7914c0ae2356dec814a9ba11f6df6b2',
            'rsig': '8c65a4058bc008a4ec7a9ddb484f5b57ff401ed7ae996e25770642c7d8694cf0ae7191b06032039689d63c8ac83e95911c252344511192fc85d8086c34914409'
        }
    }



