echo "hello openssl" > hello_openssl.txt
./deterministic_openssl_encrypt.sh -v hello_openssl.txt 
sleep 2
./deterministic_openssl_encrypt.sh -v hello_openssl.txt.32a4652ec63b896e60e82bdecbcfe97394037243cb2c8e63d7dd79b0a7d4f383.enc
