import hmac_sha512_component

input = ["9b3fea674ae24cc4a0b8fd41c35d8d4ee1739d7ff9ce100ca4acf595a56a839a3df422726e48103c7d1cebe5ada6249a353d0bd81ddb5a168bbc93a06bbf85a7", "0c79bfa8d9c63b4f471484a98651012e250ba0280335ce62dd57ef63fefd242c357339067b326fdbc40bbd9de372a1dda1448127d15ca53e23f87b232ed2ba89"]
output = ["0c79bfa8d9c63b4f471484a98651012e250ba0280335ce62dd57ef63fefd242c357339067b326fdbc40bbd9de372a1dda1448127d15ca53e23f87b232ed2ba89", "a547a4735fca6fc9a9f181908946ca32b5761587ea334a8a7d71828a6c4b0b403c633840acfc405866e90e8b269acee3fa8b1dc4f3baf31e100b17559b16fd4f"]
correct = True

for i in range (len(input)):
    if output[i] != hmac_sha512_component.hmac_sha512(input[i]):
        correct = False
        
print(correct)
