cd Benchmarks

sudo chmod "u+x" ./Elevators/dfa-elevators.sh
sudo chmod "u+x" ./TriangleTireWorld/dfa-triangle.sh
sudo chmod "u+x" ./BlocksWorld/dfa-blocksworld.sh
sudo chmod "u+x" ./BlocksWorldExtended/dfa-blocksworld.sh
sudo chmod "u+x" :/ RectangleTireworld/rect-dfa.sh

# ELEVATOR BENCHMARKS
cd Elevators

./dfa-elevators.sh

cd ..

# TRIANGLE TIRE WORLD BENCHMARKS
cd TriangleTireWorld

./dfa-triangle.sh

cd ..

# RECTANGLE TIRE WORLD BENCHMARKS
cd RectangleTireworld

./rect-dfa.sh

cd ..

# PLAIN BLOCKSWORLD BENCHMARKS
cd BlocksWorld

./dfa-blocksworld.sh

cd ..

# EXTENDED BLOCKS WORLD BENCHMARKS
cd BlocksWorldExtended

./dfa-blocksworld.sh

cd ..
