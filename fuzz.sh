function grade() {
    /home/kalaslavas/networks/KENSv3-master/build/app/kens/test-kens-transfer
    /home/kalaslavas/networks/KENSv3-master/build/app/kens/test-kens-bind-unreliable
    /home/kalaslavas/networks/KENSv3-master/build/app/kens/test-kens-handshake-unreliable
    /home/kalaslavas/networks/KENSv3-master/build/app/kens/test-kens-close-unreliable
    /home/kalaslavas/networks/KENSv3-master/build/app/kens/test-kens-transfer-unreliable
}

for i in {1..100}
do

    randomNum=$(shuf -i 0-2000000000 -n1)
    figlet "Test       $i"  
    echo $randomNum
    RANDOM_SEED=$randomNum grade
done