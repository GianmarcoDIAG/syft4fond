cd Benchmarks

sudo chmod "u+x" ./Elevators/run-elevators.sh
sudo chmod "u+x" ./TriangleTireWorld/run-triangle.sh
sudo chmod "u+x" ./BlocksWorld/blocksworld.sh
sudo chmod "u+x" ./BlocksWorldExtended/blocksworld.sh
sudo chmod "u+x" ./RectangleTireworld/rect-synth.sh

# ELEVATOR BENCHMARKS
cd Elevators

./run-elevators.sh

cd ..

# TRIANGLE TIRE WORLD BENCHMARKS
cd TriangleTireWorld

./run-triangle.sh

cd ..

# RECTANGLE TIRE WORLD BENCHMARKS
cd RectangleTireworld

./rect-synth.sh

cd ..

# PLAIN BLOCKSWORLD BENCHMARKS
cd BlocksWorld

./blocksworld.sh

cd ..

# EXTENDED BLOCKS WORLD BENCHMARKS
cd BlocksWorldExtended

./blocksworld.sh

cd ..
