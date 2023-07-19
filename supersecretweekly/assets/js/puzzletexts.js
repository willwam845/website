const texts = [
`import random

def lcg(state, multiplier, increment, modulus):
    return (multiplier * state + increment) % modulus

def xor(key, plaintext): # performs a XOR operation on the key and the plaintext
    return bytes([keybyte ^ ptbyte for keybyte, ptbyte in zip(key, plaintext)])

def to_bytes(x): # converts number to 4 bytes (base 10 -> base256)
    return x.to_bytes(4, "big")

def from_bytes(x): # converts 4 bytes to number (base256 -> base 10)
    return int.from_bytes(x, "big")

# reads the content of the secret.png file
SECRET_IMAGE = open("secret.png", "rb").read()

modulus = 0xfffffffb
multiplier = random.randrange(0, modulus) # generates multiplier, increment, state which are in the range of 0 - p
increment = random.randrange(0, modulus)
state = random.randrange(0, modulus)

# generates a one time pad using the LCG to generate bytes
otp = b""
while len(otp) < len(image):
    state = lcg(state, multiplier, increment, modulus)
    otp += to_bytes(state)

print(xor(SECRET_IMAGE, otp).hex())`,
`8744e97298ef7cc1ab909824f356472717bbecaeddca0abf187f30adfa7bd8a438eb099b12466e4cdfd515e98d9f0bc51fa55e59d4e2a963a706261c1c0fcceaac2634794387f588ba8fa62c4b168b7f45de2c3954301c4653c8d2cfab246fd6adc212399eddd999b1d748541c8532aa3c0f22ddc99a0fd4958e836a87d5c12f563decdb33211a14389b2a945995829b07eb0924480d4f665835d66d61a4785a8964d10d50d7f6f690f5965d38ed141c4838c76a81b9a0df48939d17e59f0d82139e5110856d7033811de19f68b1f51e5aa980d2cb60ba0c5957d5384a1fc6837ead7bf869ddacffe71774a1a66d310cd11b9a123502980a9dac32469302fb234ece786c5d066a5dc3823585d7927e53f405294a2bc8686a6396337c2c9ad6736e69295e94e8e320dcebb2c7ea541e8457d61f43c1dabdaa3d31ea94950f8afb0f7937f8cbb11f807ea247db91e5fa1fd3a9686a01e62127e286811b1e42a6c6321e6273be69a8053c2e0c57587e6b96f8d595d4ebb2db4589e60e18931d7acacbb9146d03c7525ad9910a41d79a7b1e23be3fa8673a49d66c9b0017a62dcf2594dd843390419898ce458256898e49615b8cf6257b2b0b2fcde8639f0b879c745aeabf3492ddfd67639bfc2c91713f430d268da2e851d4d6e5fa72db736b10ca0a8fec3bc035eb086fa3903b523cf15d6241c19ece36008bfd5d80814744b17f8b1da27082ad01709044dd96e7adb91fee5e3c41d28288847be8b412f31b4e83de16e1f49eb366d549c4fa6a0cdacdf3362c620859754d225b5a161d1b90271accde0cab1f243308c39bfc8ec3ba3b65bb5b21e4fc9089c7d4f13cf5a5f3f53ea56c98620ad45b51c3386d66d9a8ed3911fa6af786917e900aa57a6a599cd2c7b1e9e9f1fdeefceef14c8607cdf327ec7386cf21e1ae1779d02f6d45d1d32b290cfac9089524f6178986228be808629d2221984b51267bb5e28ac363422393a710d6f0097a9e06e647222f27c09d0de49578f4878000f6cd152ebb83b5d89adaf3df4fa837ba6073d86dedc8ea9de93c5c1036dad9ec0513e91ef80a8e2bf96466706f893c63cca1b5fc32960fcaae91333186595e5a127d75c667f688633a2380219810ae5b419e11b4ac0b17959628399f2b30e44bc09b9bdb6b625efac71bb9d22bae3c08508cbde105ef505217db69a37dd708190a949751962d30a66b835df4acadc68f5aaef0c014f54871af6bed7da6fe86b3b84dbe3202d9f0d12ae880a4ecdfc9ed92a69d97775e7b4d94b03f1fbfccd3b591b5e21b84d09d9e4990aa65159649e9b04ae8bb0e47c2f045b6b45d00a37a37e3d91f813a42e58114a6c0d86e25a5b313e589fa91d8`,

`from Crypto.Util.number import getPrime

SECRET_MESSAGE = b"This is a fake message. You need to use the output to recover the real message."
assert len(SECRET_MESSAGE) == 79

def to_bytes(x): # converts number to 256 bytes (base 10 -> base256)
    return x.to_bytes(256, "big")

def from_bytes(x): # converts 256 bytes to number (base256 -> base 10)
    return int.from_bytes(x, "big")

p, q = getPrime(1024), getPrime(1024) # generate two large primes
modulus = p * q # multiply them together
exponent = 3
print(modulus)
print((bytes_to_long(SECRET_MESSAGE) ** exponent) % modulus) # encrypt using RSA, by doing pt raised to the power of exponent (3) modulo the modulus`,

`25470107759908677227885059212049756476123587149099142377016782162035805692074354189159652091227375655135235368525396923393193646546513521594944466326848816352402770223540805069572455324213054236364701194222702095208890524652925607023595668703783127183044393213645665205889410585077610562587713813622057509622269267198359881821074334152602300114571365555728950484656802303612207021927556708344318318072640242977400728587542260343845271163234654779873505149665431736959069216295088527262802330309349882249615288926177838418478128072496420250629745101514345301311073925631956844826768645400016556267536370392654365461821
454147422122408638236729228778619151840745110573901635266653412884827448174696657067161863712007472045862643664187179466863186606693544670825981955322220612714094448031487713801162618522078593851990811307326192227448461688364355030506264012718298715849972685746984958365293426324609917961631777964113223482455400203888938149651008187748240438990178348789806411004166592944184851235951272579621706914933443403222482532359174060018780965662299105233528835083965863568231382797401795357662064127581799775007005491721985455877597766465099098235202614183072688947734662600789`,

`import random

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def generate_iv(block_size):
    # generates a random string of block_size letters 
    # to be used as the initialization vector for the encryption
    return "".join(random.choices(alphabet, k=block_size))

def add_key(key, plaintext_block):
    key_idxs = [alphabet.index(key_char) for key_char in key]
    pt_idxs = [alphabet.index(pt_char) for pt_char in plaintext_block]
    # adding the indexes of the key and plaintext together
    ct_idxs = [(key_idx + pt_idx) % len(alphabet) for key_idx, pt_idx in zip(key_idxs, pt_idxs)]
    # converting it back into an alphabetical string
    return "".join([alphabet[idx] for idx in ct_idxs])

def vigenere_block_chaining_encrypt(key, plaintext):
    key_length = len(key)
    # pads the plaintext
    plaintext = pad(key_length, plaintext)
    # generates an iv
    iv = generate_iv(key_length)
    # splits the plaintext into blocks of length key_length
    blocks = [plaintext[i:i+key_length] for i in range(0, len(plaintext), key_length)]
    previous_block = iv
    ciphertext = ""
    # refer to https://www.educative.io/answers/what-is-cbc
    for block in blocks:
        # adds the previous block
        # for the first block this will be the random iv
        block = add_key(previous_block, block)
        # adds the vigenere key (the block cipher encryption)
        previous_block = add_key(key, block)
        # adds the output to the final ciphertext
        ciphertext += previous_block
    # give back the plaintext with the iv
    return iv, ciphertext
    
def pad(block_size, plaintext):
    # pads the plaintext with X's until the length is a multiple of block_size
    plaintext += "X" * (-len(plaintext) % block_size)
    return plaintext

SECRET_MESSAGE = "THISISAFAKEMESSAGEYOUNEEDTOUSETHEOUTPUTTOGETTHEREALSECRETMESSAGE"
key = "AFAKEKEY"
assert len(key) == 8
assert all([char in alphabet for char in key])
assert all([char in alphabet for char in SECRET_MESSAGE])

iv, ciphertext = vigenere_block_chaining_encrypt(key, SECRET_MESSAGE)
print("iv =", iv)
print("ciphertext =", ciphertext)`,

`iv = XCVUSTKK
ciphertext = WYZCAZIXERPEDAJTTMZRCHVVOIEWJXCFMCGHDHKDDMQWDKVRVCCAWNHOWDXHTUTCXPGLDXVQXEIESEITZUQIYHTTZJWKZVUTXKCHLWOCFWGVRQMPFILDXIULREEPMOWJFYGZJFYYFNMRCQWUEZQSOWYITZTWJVMWEACAQJKJLBMOWNSWSMRWCSFZDCOWIUZYNSDCUAXEYYFTRGFMTSVKZMHKSOTOULOGOLGMGRMOVGLTDDIOWBNILNADKNBQRMHXFMGUBLOWUNECFVALJGRYMLEHDMPYDQMRNDFZKCYBFGPMJUZFECEQKMAJYUOJVEBJMCHMSVOTNDXREBMIYNGEFCGPTIMWZVTHHQHANYEWVCJNYTCJKCNRCLEHROHKCORLATGHSKIE`,

`from Crypto.Cipher import AES
import os

SECRET_MESSAGE = "THISISAFAKEMESSAGEYOUNEEDTOUSETHEOUTPUTTOGETTHEREALSECRETMESSAGE"
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
assert all([char in alphabet for char in SECRET_MESSAGE]) # makes sure the only characters in the secret message are in the alphabet

key = os.urandom(16) # generate a random key
cipher = AES.new(key, AES.MODE_ECB) # defines the AES cipher using ECB mode
for char in SECRET_MESSAGE: # encrypt the secret message character by character
    print(cipher.encrypt((char + \"\\x00\" * 15).encode()).hex()) # encrypt the character using AES-ECB mode`,

`8e413fb567af43774a0548f33512345f
fc6250cf6ffc56b0ec8ad964a9a69436
35d1cf51d69e59eb7362ba1234632091
f2ac545a54047af17df7a836c06da788
fc6250cf6ffc56b0ec8ad964a9a69436
b2537edc069d6a7cf459414bd9d68132
fc6250cf6ffc56b0ec8ad964a9a69436
abcef6667beaa72a79f2f2501cb5fdb4
b2537edc069d6a7cf459414bd9d68132
b07c2f249237d7fbcbcdf92dbcf4971e
084390594f9d8ede69731a920d38f669
8e413fb567af43774a0548f33512345f
084390594f9d8ede69731a920d38f669
8e413fb567af43774a0548f33512345f
b1d90d1a8830e296e733da7a737f89bd
6367c23c6ef24d13771d4d913aa61ede
75204bf7b031b7ed42afa3e6e0d09ac2
97722671e472f38a7de77ba3adc8514d
b2537edc069d6a7cf459414bd9d68132
aa0b5e6d8ebd25852828322e0582e757
61c4c070e25569723ec1237a58b2444c
b2537edc069d6a7cf459414bd9d68132
8e413fb567af43774a0548f33512345f
084390594f9d8ede69731a920d38f669
75204bf7b031b7ed42afa3e6e0d09ac2
fcd4ff5c50b856e22c6382cfc7b24668
aa0b5e6d8ebd25852828322e0582e757
084390594f9d8ede69731a920d38f669
75204bf7b031b7ed42afa3e6e0d09ac2
aa0b5e6d8ebd25852828322e0582e757
aa0b5e6d8ebd25852828322e0582e757
a155270568e947ad38a58cd265340a67
b2537edc069d6a7cf459414bd9d68132
fc6250cf6ffc56b0ec8ad964a9a69436
a249a9a5fa938d1ede64e155d4a84fa1
35d1cf51d69e59eb7362ba1234632091
97722671e472f38a7de77ba3adc8514d
aa0b5e6d8ebd25852828322e0582e757
b2537edc069d6a7cf459414bd9d68132
b07c2f249237d7fbcbcdf92dbcf4971e
084390594f9d8ede69731a920d38f669
8e413fb567af43774a0548f33512345f
ddfe22f2283da4f48ef2fd804694e391
f2ac545a54047af17df7a836c06da788
35d1cf51d69e59eb7362ba1234632091
084390594f9d8ede69731a920d38f669
75204bf7b031b7ed42afa3e6e0d09ac2
b2537edc069d6a7cf459414bd9d68132
aa0b5e6d8ebd25852828322e0582e757
61c4c070e25569723ec1237a58b2444c
b2537edc069d6a7cf459414bd9d68132
a76d4d61bf869a8ee2e5431ce64417b4
aa0b5e6d8ebd25852828322e0582e757
35d1cf51d69e59eb7362ba1234632091
f2ac545a54047af17df7a836c06da788
f2ac545a54047af17df7a836c06da788
ac62d6e3cec72fa724c26d85e2de9012
f2ac545a54047af17df7a836c06da788
fc6250cf6ffc56b0ec8ad964a9a69436
75204bf7b031b7ed42afa3e6e0d09ac2
97b50503eb91515245ea9ad635f6d923
8e413fb567af43774a0548f33512345f
fc6250cf6ffc56b0ec8ad964a9a69436
b2537edc069d6a7cf459414bd9d68132
b07c2f249237d7fbcbcdf92dbcf4971e
35d1cf51d69e59eb7362ba1234632091
b2537edc069d6a7cf459414bd9d68132
ac62d6e3cec72fa724c26d85e2de9012
fc6250cf6ffc56b0ec8ad964a9a69436
6367c23c6ef24d13771d4d913aa61ede
fcd4ff5c50b856e22c6382cfc7b24668
35d1cf51d69e59eb7362ba1234632091
75204bf7b031b7ed42afa3e6e0d09ac2
ddfe22f2283da4f48ef2fd804694e391
aa0b5e6d8ebd25852828322e0582e757
a76d4d61bf869a8ee2e5431ce64417b4
abcef6667beaa72a79f2f2501cb5fdb4
fc6250cf6ffc56b0ec8ad964a9a69436
a76d4d61bf869a8ee2e5431ce64417b4
a249a9a5fa938d1ede64e155d4a84fa1
abcef6667beaa72a79f2f2501cb5fdb4
a76d4d61bf869a8ee2e5431ce64417b4
aa0b5e6d8ebd25852828322e0582e757
db03fcdcf7a092e610f044156896ed2e
6367c23c6ef24d13771d4d913aa61ede
aa0b5e6d8ebd25852828322e0582e757
75204bf7b031b7ed42afa3e6e0d09ac2
fcd4ff5c50b856e22c6382cfc7b24668
ac62d6e3cec72fa724c26d85e2de9012
35d1cf51d69e59eb7362ba1234632091
75204bf7b031b7ed42afa3e6e0d09ac2
35d1cf51d69e59eb7362ba1234632091
f2ac545a54047af17df7a836c06da788
ac62d6e3cec72fa724c26d85e2de9012
8e413fb567af43774a0548f33512345f
084390594f9d8ede69731a920d38f669
8e413fb567af43774a0548f33512345f
fc6250cf6ffc56b0ec8ad964a9a69436
75204bf7b031b7ed42afa3e6e0d09ac2
b2537edc069d6a7cf459414bd9d68132
b07c2f249237d7fbcbcdf92dbcf4971e
084390594f9d8ede69731a920d38f669
8e413fb567af43774a0548f33512345f
35d1cf51d69e59eb7362ba1234632091
75204bf7b031b7ed42afa3e6e0d09ac2
ac62d6e3cec72fa724c26d85e2de9012
1681822340006c4aaac4a787d38632e7
35d1cf51d69e59eb7362ba1234632091
ac62d6e3cec72fa724c26d85e2de9012
084390594f9d8ede69731a920d38f669
b07c2f249237d7fbcbcdf92dbcf4971e
fc6250cf6ffc56b0ec8ad964a9a69436
ddfe22f2283da4f48ef2fd804694e391
aa0b5e6d8ebd25852828322e0582e757
b2537edc069d6a7cf459414bd9d68132
b07c2f249237d7fbcbcdf92dbcf4971e
084390594f9d8ede69731a920d38f669
8e413fb567af43774a0548f33512345f
1681822340006c4aaac4a787d38632e7
35d1cf51d69e59eb7362ba1234632091
8e413fb567af43774a0548f33512345f
75204bf7b031b7ed42afa3e6e0d09ac2
b2537edc069d6a7cf459414bd9d68132
b2537edc069d6a7cf459414bd9d68132
fc6250cf6ffc56b0ec8ad964a9a69436
fc6250cf6ffc56b0ec8ad964a9a69436
b07c2f249237d7fbcbcdf92dbcf4971e
35d1cf51d69e59eb7362ba1234632091
a76d4d61bf869a8ee2e5431ce64417b4
a155270568e947ad38a58cd265340a67
aa0b5e6d8ebd25852828322e0582e757
8e413fb567af43774a0548f33512345f
ddfe22f2283da4f48ef2fd804694e391
aa0b5e6d8ebd25852828322e0582e757
fcd4ff5c50b856e22c6382cfc7b24668
084390594f9d8ede69731a920d38f669
35d1cf51d69e59eb7362ba1234632091
f2ac545a54047af17df7a836c06da788
f2ac545a54047af17df7a836c06da788
ac62d6e3cec72fa724c26d85e2de9012
084390594f9d8ede69731a920d38f669
abcef6667beaa72a79f2f2501cb5fdb4
ac62d6e3cec72fa724c26d85e2de9012
fc6250cf6ffc56b0ec8ad964a9a69436
6367c23c6ef24d13771d4d913aa61ede
8e413fb567af43774a0548f33512345f
fc6250cf6ffc56b0ec8ad964a9a69436
f2ac545a54047af17df7a836c06da788
695b918897337b345cef6e4d0549187b
aa0b5e6d8ebd25852828322e0582e757
a155270568e947ad38a58cd265340a67
b2537edc069d6a7cf459414bd9d68132
b07c2f249237d7fbcbcdf92dbcf4971e
aa0b5e6d8ebd25852828322e0582e757
7ea90731233366e181a020e8cb86b9ce
35d1cf51d69e59eb7362ba1234632091
7ea90731233366e181a020e8cb86b9ce
ac62d6e3cec72fa724c26d85e2de9012
695b918897337b345cef6e4d0549187b
35d1cf51d69e59eb7362ba1234632091
a76d4d61bf869a8ee2e5431ce64417b4
084390594f9d8ede69731a920d38f669
35d1cf51d69e59eb7362ba1234632091
75204bf7b031b7ed42afa3e6e0d09ac2
b2537edc069d6a7cf459414bd9d68132
ddfe22f2283da4f48ef2fd804694e391
a76d4d61bf869a8ee2e5431ce64417b4
fc6250cf6ffc56b0ec8ad964a9a69436
695b918897337b345cef6e4d0549187b
084390594f9d8ede69731a920d38f669
a155270568e947ad38a58cd265340a67
aa0b5e6d8ebd25852828322e0582e757
a155270568e947ad38a58cd265340a67
35d1cf51d69e59eb7362ba1234632091
75204bf7b031b7ed42afa3e6e0d09ac2
a155270568e947ad38a58cd265340a67
ac62d6e3cec72fa724c26d85e2de9012
aa0b5e6d8ebd25852828322e0582e757
8e413fb567af43774a0548f33512345f
ac62d6e3cec72fa724c26d85e2de9012
fc6250cf6ffc56b0ec8ad964a9a69436
6367c23c6ef24d13771d4d913aa61ede
8e413fb567af43774a0548f33512345f
b07c2f249237d7fbcbcdf92dbcf4971e
fc6250cf6ffc56b0ec8ad964a9a69436
6367c23c6ef24d13771d4d913aa61ede
f2ac545a54047af17df7a836c06da788
a155270568e947ad38a58cd265340a67
ddfe22f2283da4f48ef2fd804694e391
a76d4d61bf869a8ee2e5431ce64417b4
fc6250cf6ffc56b0ec8ad964a9a69436
7ea90731233366e181a020e8cb86b9ce
35d1cf51d69e59eb7362ba1234632091
7ea90731233366e181a020e8cb86b9ce
f2ac545a54047af17df7a836c06da788
ac62d6e3cec72fa724c26d85e2de9012
75204bf7b031b7ed42afa3e6e0d09ac2
fc6250cf6ffc56b0ec8ad964a9a69436
b2537edc069d6a7cf459414bd9d68132
6367c23c6ef24d13771d4d913aa61ede
8e413fb567af43774a0548f33512345f
aa0b5e6d8ebd25852828322e0582e757
aa0b5e6d8ebd25852828322e0582e757
fcd4ff5c50b856e22c6382cfc7b24668
7ea90731233366e181a020e8cb86b9ce
a249a9a5fa938d1ede64e155d4a84fa1
fc6250cf6ffc56b0ec8ad964a9a69436
a155270568e947ad38a58cd265340a67
aa0b5e6d8ebd25852828322e0582e757
1681822340006c4aaac4a787d38632e7
b07c2f249237d7fbcbcdf92dbcf4971e
aa0b5e6d8ebd25852828322e0582e757
75204bf7b031b7ed42afa3e6e0d09ac2
6367c23c6ef24d13771d4d913aa61ede
8e413fb567af43774a0548f33512345f
084390594f9d8ede69731a920d38f669
75204bf7b031b7ed42afa3e6e0d09ac2
97b50503eb91515245ea9ad635f6d923
35d1cf51d69e59eb7362ba1234632091
aa0b5e6d8ebd25852828322e0582e757
8e413fb567af43774a0548f33512345f
7ea90731233366e181a020e8cb86b9ce
aa0b5e6d8ebd25852828322e0582e757
fcd4ff5c50b856e22c6382cfc7b24668
35d1cf51d69e59eb7362ba1234632091
6367c23c6ef24d13771d4d913aa61ede
8e413fb567af43774a0548f33512345f
aa0b5e6d8ebd25852828322e0582e757
084390594f9d8ede69731a920d38f669
b2537edc069d6a7cf459414bd9d68132
8e413fb567af43774a0548f33512345f
6367c23c6ef24d13771d4d913aa61ede
8e413fb567af43774a0548f33512345f
6367c23c6ef24d13771d4d913aa61ede
35d1cf51d69e59eb7362ba1234632091
f2ac545a54047af17df7a836c06da788
f2ac545a54047af17df7a836c06da788
ac62d6e3cec72fa724c26d85e2de9012
7ea90731233366e181a020e8cb86b9ce
35d1cf51d69e59eb7362ba1234632091
a155270568e947ad38a58cd265340a67
8e413fb567af43774a0548f33512345f
aa0b5e6d8ebd25852828322e0582e757
35d1cf51d69e59eb7362ba1234632091
a76d4d61bf869a8ee2e5431ce64417b4
fcd4ff5c50b856e22c6382cfc7b24668
b07c2f249237d7fbcbcdf92dbcf4971e
6367c23c6ef24d13771d4d913aa61ede
ddfe22f2283da4f48ef2fd804694e391
aa0b5e6d8ebd25852828322e0582e757
fcd4ff5c50b856e22c6382cfc7b24668
7ea90731233366e181a020e8cb86b9ce
ddfe22f2283da4f48ef2fd804694e391
aa0b5e6d8ebd25852828322e0582e757
75204bf7b031b7ed42afa3e6e0d09ac2
97b50503eb91515245ea9ad635f6d923
6367c23c6ef24d13771d4d913aa61ede
084390594f9d8ede69731a920d38f669
75204bf7b031b7ed42afa3e6e0d09ac2
084390594f9d8ede69731a920d38f669
abcef6667beaa72a79f2f2501cb5fdb4
ac62d6e3cec72fa724c26d85e2de9012
fc6250cf6ffc56b0ec8ad964a9a69436
6367c23c6ef24d13771d4d913aa61ede
1681822340006c4aaac4a787d38632e7
35d1cf51d69e59eb7362ba1234632091
75204bf7b031b7ed42afa3e6e0d09ac2
b2537edc069d6a7cf459414bd9d68132
b2537edc069d6a7cf459414bd9d68132
fc6250cf6ffc56b0ec8ad964a9a69436
8e413fb567af43774a0548f33512345f
aa0b5e6d8ebd25852828322e0582e757
aa0b5e6d8ebd25852828322e0582e757
35d1cf51d69e59eb7362ba1234632091
75204bf7b031b7ed42afa3e6e0d09ac2
aa0b5e6d8ebd25852828322e0582e757
61c4c070e25569723ec1237a58b2444c
35d1cf51d69e59eb7362ba1234632091
a249a9a5fa938d1ede64e155d4a84fa1
ddfe22f2283da4f48ef2fd804694e391
f2ac545a54047af17df7a836c06da788
aa0b5e6d8ebd25852828322e0582e757
fc6250cf6ffc56b0ec8ad964a9a69436
abcef6667beaa72a79f2f2501cb5fdb4
b07c2f249237d7fbcbcdf92dbcf4971e
fc6250cf6ffc56b0ec8ad964a9a69436
1681822340006c4aaac4a787d38632e7
6367c23c6ef24d13771d4d913aa61ede
8e413fb567af43774a0548f33512345f
084390594f9d8ede69731a920d38f669
75204bf7b031b7ed42afa3e6e0d09ac2
97b50503eb91515245ea9ad635f6d923
aa0b5e6d8ebd25852828322e0582e757
fcd4ff5c50b856e22c6382cfc7b24668
7ea90731233366e181a020e8cb86b9ce
fcd4ff5c50b856e22c6382cfc7b24668
35d1cf51d69e59eb7362ba1234632091
75204bf7b031b7ed42afa3e6e0d09ac2
f2ac545a54047af17df7a836c06da788
aa0b5e6d8ebd25852828322e0582e757
35d1cf51d69e59eb7362ba1234632091
97722671e472f38a7de77ba3adc8514d
8e413fb567af43774a0548f33512345f
b2537edc069d6a7cf459414bd9d68132
6367c23c6ef24d13771d4d913aa61ede
abcef6667beaa72a79f2f2501cb5fdb4
abcef6667beaa72a79f2f2501cb5fdb4
f2ac545a54047af17df7a836c06da788
084390594f9d8ede69731a920d38f669
97722671e472f38a7de77ba3adc8514d
aa0b5e6d8ebd25852828322e0582e757
084390594f9d8ede69731a920d38f669
a249a9a5fa938d1ede64e155d4a84fa1
35d1cf51d69e59eb7362ba1234632091
97b50503eb91515245ea9ad635f6d923
aa0b5e6d8ebd25852828322e0582e757
8e413fb567af43774a0548f33512345f
fcd4ff5c50b856e22c6382cfc7b24668
fc6250cf6ffc56b0ec8ad964a9a69436
a249a9a5fa938d1ede64e155d4a84fa1
ddfe22f2283da4f48ef2fd804694e391
35d1cf51d69e59eb7362ba1234632091
a76d4d61bf869a8ee2e5431ce64417b4
aa0b5e6d8ebd25852828322e0582e757
a155270568e947ad38a58cd265340a67
b2537edc069d6a7cf459414bd9d68132
fc6250cf6ffc56b0ec8ad964a9a69436
b2537edc069d6a7cf459414bd9d68132
b07c2f249237d7fbcbcdf92dbcf4971e
084390594f9d8ede69731a920d38f669
8e413fb567af43774a0548f33512345f
695b918897337b345cef6e4d0549187b
aa0b5e6d8ebd25852828322e0582e757
a76d4d61bf869a8ee2e5431ce64417b4
ac62d6e3cec72fa724c26d85e2de9012
fcd4ff5c50b856e22c6382cfc7b24668
fc6250cf6ffc56b0ec8ad964a9a69436
75204bf7b031b7ed42afa3e6e0d09ac2
b2537edc069d6a7cf459414bd9d68132
a76d4d61bf869a8ee2e5431ce64417b4
084390594f9d8ede69731a920d38f669
695b918897337b345cef6e4d0549187b
aa0b5e6d8ebd25852828322e0582e757
a155270568e947ad38a58cd265340a67
aa0b5e6d8ebd25852828322e0582e757
61c4c070e25569723ec1237a58b2444c
35d1cf51d69e59eb7362ba1234632091
a249a9a5fa938d1ede64e155d4a84fa1
ddfe22f2283da4f48ef2fd804694e391
f2ac545a54047af17df7a836c06da788
aa0b5e6d8ebd25852828322e0582e757
b2537edc069d6a7cf459414bd9d68132
b07c2f249237d7fbcbcdf92dbcf4971e
35d1cf51d69e59eb7362ba1234632091
b2537edc069d6a7cf459414bd9d68132
084390594f9d8ede69731a920d38f669
8e413fb567af43774a0548f33512345f
ddfe22f2283da4f48ef2fd804694e391
6367c23c6ef24d13771d4d913aa61ede
a76d4d61bf869a8ee2e5431ce64417b4
aa0b5e6d8ebd25852828322e0582e757
f2ac545a54047af17df7a836c06da788
ac62d6e3cec72fa724c26d85e2de9012
b07c2f249237d7fbcbcdf92dbcf4971e
aa0b5e6d8ebd25852828322e0582e757
a76d4d61bf869a8ee2e5431ce64417b4
aa0b5e6d8ebd25852828322e0582e757
b2537edc069d6a7cf459414bd9d68132
fc6250cf6ffc56b0ec8ad964a9a69436
8e413fb567af43774a0548f33512345f
b07c2f249237d7fbcbcdf92dbcf4971e
fc6250cf6ffc56b0ec8ad964a9a69436
1681822340006c4aaac4a787d38632e7
b07c2f249237d7fbcbcdf92dbcf4971e
fc6250cf6ffc56b0ec8ad964a9a69436
1681822340006c4aaac4a787d38632e7
b2537edc069d6a7cf459414bd9d68132
b07c2f249237d7fbcbcdf92dbcf4971e
aa0b5e6d8ebd25852828322e0582e757
35d1cf51d69e59eb7362ba1234632091
b2537edc069d6a7cf459414bd9d68132
b2537edc069d6a7cf459414bd9d68132
35d1cf51d69e59eb7362ba1234632091
fcd4ff5c50b856e22c6382cfc7b24668
97722671e472f38a7de77ba3adc8514d
084390594f9d8ede69731a920d38f669
a155270568e947ad38a58cd265340a67
aa0b5e6d8ebd25852828322e0582e757
35d1cf51d69e59eb7362ba1234632091
1681822340006c4aaac4a787d38632e7
fc6250cf6ffc56b0ec8ad964a9a69436
a76d4d61bf869a8ee2e5431ce64417b4
97722671e472f38a7de77ba3adc8514d
8e413fb567af43774a0548f33512345f
fc6250cf6ffc56b0ec8ad964a9a69436
b07c2f249237d7fbcbcdf92dbcf4971e
35d1cf51d69e59eb7362ba1234632091
f2ac545a54047af17df7a836c06da788
8e413fb567af43774a0548f33512345f
fc6250cf6ffc56b0ec8ad964a9a69436
b2537edc069d6a7cf459414bd9d68132
b07c2f249237d7fbcbcdf92dbcf4971e
aa0b5e6d8ebd25852828322e0582e757
35d1cf51d69e59eb7362ba1234632091
75204bf7b031b7ed42afa3e6e0d09ac2
8e413fb567af43774a0548f33512345f
1681822340006c4aaac4a787d38632e7
aa0b5e6d8ebd25852828322e0582e757
a76d4d61bf869a8ee2e5431ce64417b4
084390594f9d8ede69731a920d38f669
8e413fb567af43774a0548f33512345f
fc6250cf6ffc56b0ec8ad964a9a69436
695b918897337b345cef6e4d0549187b
aa0b5e6d8ebd25852828322e0582e757
a76d4d61bf869a8ee2e5431ce64417b4
8e413fb567af43774a0548f33512345f
b2537edc069d6a7cf459414bd9d68132
35d1cf51d69e59eb7362ba1234632091
abcef6667beaa72a79f2f2501cb5fdb4
abcef6667beaa72a79f2f2501cb5fdb4
aa0b5e6d8ebd25852828322e0582e757
a155270568e947ad38a58cd265340a67`,

`import os

PUBLIC_MESSAGE = b"Hello! This is a real message. However, obtaining this won't give you anything; you need to find the secret message"
SECRET_MESSAGE = b"This is a fake message. The output produced is by running this script with the real message."

one_time_pad = os.urandom(len(PUBLIC_MESSAGE)) # generates a completely random key to be used in the XOR cipher

def xor(key, plaintext): # performs a XOR operation on the key and the plaintext
    return bytes([keybyte ^ ptbyte for keybyte, ptbyte in zip(key, plaintext)])

print(xor(one_time_pad, PUBLIC_MESSAGE).hex()) # outputs the result of xor(one_time_pad, public_message) as a hex string
print(xor(one_time_pad, SECRET_MESSAGE).hex())`,

`bb3652a6ccc9729d566062032f38015a24c66639f8ed9e0ddf97183c08584cf845a5a7fa76d0ec819f2628db218430fb29b810d46f9997b1a20663801134a0e44134ef0972842dffae55cd5913b8f922a429b921184062d19262c94eaf81cbbb8586e0615211f4f7409a2a40ec0804e3b7fde9
b03c50add18926bc5268654a2925521b6bda233efda39701c283592f051f1f9059b7a1fe76d6e0cc95372fdb2f8f77b51af0019c6784c4b1a81a648d5e26e9fc4171f24673cb6ce2a243c85909ffab71fd028940226d27e5f758e7229da1e08c`,

`⬛⬛🟩⬛⬛	Often balanced with rewards
🟩⬛⬛⬛⬛	McDonalds burger containing poached protein, found in India
⬛🟨⬛🟩⬛	C4H9
⬛⬛⬛⬛⬛	Red breasted bird
⬛⬛⬛⬛⬛	XX - II
⬛⬛⬛🟨⬛	Shade of purple, or a plant`,

`Houses are numbered 1-6.
All puzzles were solved at least once.
Everyone solved at least 1 puzzle.
In total there were 18 correct answers submitted across all puzzles.
Alice solved the most puzzles, and Eve solved the least.
Everyone solved The Verdict, except for one person, who likes CRYPTIC CROSSWORDS.
The Verdict was the only puzzle to get more than 2 solves.
Alice was the only person to solve the same number of puzzles as her house number.
Bob solved The Skeleton.
Charlie solved all puzzles with a prime number of characters in their final answer.
David did not solve any puzzle with a number in the final answer.
Eve lives next to someone who solved the puzzle with a number in its name.
Mallory lives next to someone she shared a solve with.
Mallory submitted correct answers that totalled 69 characters.
Mallory only solved 1 puzzle made by anyone with a name longer than 7 characters.
Mallory was on holiday during Feburary 2023, and couldn't solve any puzzles during that time.
Mallory and Alice have no solves in common.
Bob, Charlie and David have no solves in common apart from one, which all three of them solved.
Combined, Bob, Charlie and David solved a Fibonacci number of unique puzzles.
The person in house 1 solved 3 puzzles.
The person in house 3 solved the puzzle with the longest answer.
The person in house 6 likes RUNAROUNDS.
The person in house 6 solved all puzzles made by someone with a k in their name.
The only solver of The Shop likes DROPQUOTES.
The only solver of The Eatery lives next to the person who likes METAMETAS.
The person who likes ARROW SUDOKUS puzzles had all their solves be made by someone with an "a" in their name
The person who lives next to Alice solved the puzzle made by the person with a special character in their name.
Someone hacked Bob and submitted all of his answers!
Someone likes MISCELLANEOUS puzzles.`,

`Professional reviewer [6]
??????? [7]
Type of chemical bond [5]
Vegetables that make you cry [6]


??????? [7]
Helium filled party decoration [7]
Close-fitting knitted cap [6]
Number represented by giga prefix [7]
Noble gas often used in signs [4]


Disney film featuring a genie [7]
Place for cold cuts [4]
??????? [7]
Without clothes [5]


Blood vessel type [6]
Home planet [5]
Chemical compound with two alkyl groups joined to oxygen [5]
Very energetic [5]
Beats rock in a hand game [5]
Incisors or molars [5]
??????? [7]
Greek letter often used to represent an angle [5]


County east of London [5]
Formally remove from school [5]
Google phone [5]
Fairy [5]
Seductively attractive [4]
????????? [9]
II^V [5]


Bean used for chocolate [5]
????????? [9]
Place for betting chips [6]
Used in crafting minecraft torches [4]
Physicist Newton [5]
MRI or CT [4]
Knuckles' blue counterpart [5]


Cells that line the bronchus [5]
Vote into office [5]
????????? [9]
Forbidden by law [7]
Slanted text [6]


False religion [4]
The L of BLT [7]
?????? [6]
Offspring of donkey + horse [4]
Informal term for stomach [5]


Not your ally [5]
?????? [6]
Mickey, e.g [5]
Touch or taste [5]


Place for duels in ancient times [5]
Mom or dad [6]
Gift, or right now [7]
North Pole resident [5]
???????? [8]


Damp or wet [5]
Keeps an eye on, or part of a gaming set up [8]
Constallation featuring a belt [5]
Capital of Ontario [7]
??????? [7]`,

`import random

def lcg(state, multiplier, increment, modulus):
    return (multiplier * state + increment) % modulus

def to_bytes(x): # converts number to 4 bytes (base 10 -> base256)
    return x.to_bytes(4, "big")

def from_bytes(x): # converts 4 bytes to number (base256 -> base 10)
    return int.from_bytes(x, "big")

SECRET_MESSAGE = "ThisFakeAnsw"
modulus = 0xfffffffb
multiplier = from_bytes(SECRET_MESSAGE.encode()[:4]) # generates multiplier, increment, state using the secret_message
increment = from_bytes(SECRET_MESSAGE.encode()[4:8])
state = from_bytes(SECRET_MESSAGE.encode()[8:])

output = []
for i in range(4):
    state = lcg(state, multiplier, increment, modulus)
    output.append(state)

print(output)`,
`[3269947243, 1586749721, 3144236226, 1915197705]`,
`from Crypto.Util.number import getPrime

SECRET_MESSAGE = b"This is a fake message. You need to use the output in order to recover the real message. Anyway, here's some junk so that the message is of appropriate length. enigmatics is so cool! I love engimatics."
assert len(SECRET_MESSAGE) == 201

def bytes_to_long(byte_string):
    return int(byte_string.hex(), 16)

def long_to_bytes(integer):
    return bytes.fromhex(hex(integer)[2:])

p, q = getPrime(1024), getPrime(1024) # generate two large primes
modulus = p * q # multiply them together
exponent = 1
print(modulus)
print((bytes_to_long(SECRET_MESSAGE) ** exponent) % modulus) # encrypt using RSA, by doing pt raised to the power of exponent (3) modulo the modulus`,
`17845097488596639845518134386175507154138020633028978410599492028517185249762037941921834310735343524416248353253297004195034415311652348836343210124772724156933556474501204108447031043065370143020118340841009308082569275068337588680708705817539633555913471436360805549182752511044555690261882864681449364372080830664440708636199339903319195562063527895839659283871512345578702252921421500462837606285164842704956629612659250186753272777602890359528736658773682337895707675287899998993856744285265279750099474752160466960081514750255995189850248416415689506400427175761412047149724013540570133933037768024101486378921
4464546116043465080725086728135721186421551998994298185795184113369194141931808356261973191771603232472347856620304536340486415244048057136394402648172582167263525763507999892546695785155389836019857067059329844145393639738027314536187312344281320972310479504663255912873389143515679290355306708678056818192416702976443834017292358856475472481820752295754775314065426809062967610934573792037574956623980674960412246584165785102773939556164134182466021463864399364067784086516913366386`,
`OUADCWDGVYALOQPYBNUSHVGSVJSOHLNMKQIIMPUGTBUNZBJWNAXLVPCDTKZGXQVKXXABTJNQBNQHTZFWAZANXWWLWLFHXBGUPTUCTTEZIRXEGOGKAUUFRWWUITEOEDGABOIONTFTMBQRRXTGCJMLLWKSXUXOZQBWNUDTAMOWAYKCHLGXQRXEWEKLPIAMFMPLAHGTBBTAMJFOFIMWQZQALGVGNUXLHECDAUKONKCFAANMBBCFACQRVQRZMXNLHKMUPGUNBVI`,
`from Crypto.Cipher import AES
import os

def string_to_binary(s):
    return "".join([bin(ord(x))[2:].zfill(8) for x in s])

SECRET_MESSAGE = string_to_binary("THISISAFAKEMESSAGEYOUNEEDTOUSETHEOUTPUTTOGETTHEREALSECRETMESSAGE")
alphabet = "01"
assert all([char in alphabet for char in SECRET_MESSAGE]) # makes sure the only characters in the secret message are in the alphabet

key = os.urandom(16) # generate a random key
cipher = AES.new(key, AES.MODE_ECB) # defines the AES cipher using ECB mode
for char in SECRET_MESSAGE: # encrypt the secret message character by character
    print(cipher.encrypt((char + \"\\x00\" * 15).encode()).hex()) # encrypt the character using AES-ECB mode`,
`6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
77749516043738c6497bb3587a55a623
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2
6a7bfbb1f1839b16ce8d6ca308f33bd2`
]
    