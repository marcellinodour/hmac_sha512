import hmac_sha512_component

input = ["9b3fea674ae24cc4a0b8fd41c35d8d4ee1739d7ff9ce100ca4acf595a56a839a3df422726e48103c7d1cebe5ada6249a353d0bd81ddb5a168bbc93a06bbf85a7"]
key = "hello"
output = ["ce16a1fb0e76819983b0c163aeb38b36c2b27dedb58d8b9a8ab97e9811d9e0b5168dbd65876ca2f91f61146e27a529428a7d9178fb6d06cfda7da20a9ede6abf"]
correct = True

for i in range (len(input)):
    if output[i] != hmac_sha512_component.hmac_sha512(key, input[i]):
        correct = False
        
print(correct)
