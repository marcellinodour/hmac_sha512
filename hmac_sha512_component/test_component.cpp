#include "hmac_sha512_component.hpp"
#include <iostream>

using namespace std;

int main(){

    char input[1][256] = {"9b3fea674ae24cc4a0b8fd41c35d8d4ee1739d7ff9ce100ca4acf595a56a839a3df422726e48103c7d1cebe5ada6249a353d0bd81ddb5a168bbc93a06bbf85a7"};
    string output[1] = {"ce16a1fb0e76819983b0c163aeb38b36c2b27dedb58d8b9a8ab97e9811d9e0b5168dbd65876ca2f91f61146e27a529428a7d9178fb6d06cfda7da20a9ede6abf"};
    string key = "hello";
    bool result = true;

    for(int i = 0; i < sizeof(input)/sizeof(input[0]); i++){
        if(hmac_sha512(key, input[i]).compare(output[i])!=0){
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
