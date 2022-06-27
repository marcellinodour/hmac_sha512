#include "hmac_sha512_component.hpp"
#include <iostream>

using namespace std;

int main(){

    char input[2][256] = {"9b3fea674ae24cc4a0b8fd41c35d8d4ee1739d7ff9ce100ca4acf595a56a839a3df422726e48103c7d1cebe5ada6249a353d0bd81ddb5a168bbc93a06bbf85a7", "0c79bfa8d9c63b4f471484a98651012e250ba0280335ce62dd57ef63fefd242c357339067b326fdbc40bbd9de372a1dda1448127d15ca53e23f87b232ed2ba89"};
    string output[2] = {"39a8135e0f819cc9583dabd86d7ce83948d3623b90b5523bc526ec65acbfd05271b52756045d03830589976b53b5e1a8840ffb6e505ac6f76beb75fb0fcb7fc7", "1511b152a83eb955ebc92b8b8577d40dd5ed9886021660f863d5e85c455ac4a9fcaf36fb716f3ef847e13c9c6806a741c32c128e81829323f7e121a30e7d4fae"};
    string key = "hello";
    bool result = true;

    for(int i = 0; i < sizeof(input)/sizeof(input[0]); i++){
        if(hmac_sha512(input[i]).compare(output[i])!=0){
		result = false;
        }
    }

    if(result){
        cout << "Test succes" << endl;
    }else {
        cout << "Test failed" << endl;
    }

    return 0;
}
