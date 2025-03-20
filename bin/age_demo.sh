echo "hello age" > hello_age.txt
./deterministic_age.sh -v hello_age.txt 
sleep 1
./deterministic_age.sh -v hello_age.txt.age 
