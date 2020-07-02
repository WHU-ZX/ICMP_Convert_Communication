from sm4 import SM4Key

key0 = SM4Key(b"abcdefghijklmnop")

str = key0.encrypt(b"zouxin whu 20173", padding=True)

print(str)
print(len(str))

str2 = key0.decrypt(str, padding=True)

print(str2)