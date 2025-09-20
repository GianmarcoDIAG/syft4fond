# LTLf's Syft4FOND

This version of Syft4FOND accepts LTLf goals as inputs.  

# Usage

The output of `./syft4fond --help` is:

```
syft4fond-ltlf: a tool for LTLf reactive synthesis in FOND planning domains
Usage: ./syft4fond [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  -d,--domain-file TEXT:FILE REQUIRED
                              Path to PDDL domain file
  -p,--problem-file TEXT:FILE REQUIRED
                              Path to PDDL problem file
  -g,--goal-file TEXT:FILE REQUIRED
                              Path to LTLf goal file
  -o,--out-file TEXT          Path to output .csv file. Stores:
                              1. PDDL domain file
                              2. PDDL problem file
                              3. Run time (secs)
                              4. PDDL parsing (secs)
                              5. PDDL2DFA (secs)
                              6. Synthesis (secs)
                              7. Realizability (0,1)
``` 

The output of pddl2ltlf --help is the following:

```
pddl2ltlf: a tool to convert PDDL planning domain specifications into LTLf
Usage: ./pddl2ltlf [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  -d,--domain-file TEXT:FILE REQUIRED
                              Path to PDDL domain file
  -p,--problem-file TEXT:FILE REQUIRED
                              Path to PDDL problem file
  -g,--goal-file TEXT:FILE REQUIRED
                              Path to LTLf goal file
  -l,--ltlf-file TEXT         Path to output LTLf formula file
  -t,--part-file TEXT         Path to output partition file
```

To convert PDDL specification into LTLf, you should use a command like this:

```
/pddl2ltlf -d domain.pddl -p test1.pddl -g test1.ltlf -l formula.ltlf -t partition.part
```

Where:
- `domain.pddl` is the file that contains the PDDL specification of the domain using a first-order syntax;
- `test1.pddl` is the file that contains the instance of the PDDL specification, i.e., the objects of the problem;
- `test1.ltlf` contains the LTLf goal;
- `formula.ltlf` is the output file that contains of the formula that contains both PDDL and LTLf;
- `partition.part` is the output file that contains the partitioning of the variables of the problem.

# Build from source

Compilation instruction using CMake (https://cmake.org/). We recommend using Ubuntu 22.04 LTS.

## Install the dependencies

### Flex and Bison

The project uses Flex and Bison for parsing purposes.

First check that you have them: `whereis flex bison`

If no item occurs, then you have to install them: `sudo apt-get install -f flex bison`

### CUDD 3.0.0

The project depends on CUDD 3.0.0. To install it, run the following commands

```
wget https://github.com/whitemech/cudd/releases/download/v3.0.0/cudd_3.0.0_linux-amd64.tar.gz
tar -xf cudd_3.0.0_linux-amd64.tar.gz
cd cudd_3.0.0_linux-amd64
sudo cp -P lib/* /usr/local/lib/
sudo cp -Pr include/* /usr/local/include/
```

Otherwise, build from source (customize `PREFIX` variable as you see fit).

```
git clone https://github.com/whitemech/cudd && cd cudd
PREFIX="/usr/local"
./configure --enable-silent-rules --enable-obj --enable-dddmp --prefix=$PREFIX
sudo make install
```

If you get an error about aclocal, this might be due to either

* Not having automake: `sudo apt-get install automake`
* Needing to reconfigure, do this before `configuring: autoreconf -i`
* Using a version of aclocal other than 1.14: modify the version 1.14 in configure accordingly.

### MONA

The projects depends on the MONA library, version v1.4 (patch 19). We require that the library is compiled with different values for parameters such as `MAX_VARIABLES`, and `BDD_MAX_TOTAL_TABLE_SIZE` (you can have a look at the details at https://github.com/whitemech/MONA/releases/tag/v1.4-19.dev0).

To install the MONA library, run the following commands:

```
wget https://github.com/whitemech/MONA/releases/download/v1.4-19.dev0/mona_1.4-19.dev0_linux-amd64.tar.gz
tar -xf mona_1.4-19.dev0_linux-amd64.tar.gz
cd mona_1.4-19.dev0_linux-amd64
sudo cp -P lib/* /usr/local/lib/
sudo cp -Pr include/* /usr/local/include
```

### SPOT

The project relies on SPOT (https://spot.lre.epita.fr/). To install it, follows the instructions at https://spot.lre.epita.fr/install.html

### Graphviz

The project uses Graphviz to display automata and strategies. Follow the install instructions on the official website: https://graphviz.gitlab.io/download/.

On Ubuntu, this should work:

```
sudo apt-get install libgraphviz-dev
```

### Syft

The project depends on Syft. First, install the Boost libraries.

```
sudo apt-get install libboost-dev-all
```

For further information see https://www.boost.org/ 

Install Syft with

```
git clone https://github.com/whitemech/Syft.git
cd Syft
git checkout v0.1.1
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j
sudo make install
```

### Lydia:

Clone Lydia within the submodules folder.

```
git clone https://github.com/whitemech/lydia.git --recursive
```

Update permissions for files in submodules with `sudo chmod "+rwx" -R submodules`

### Building

```
mkdir build && cd build
cmake ..
make -j2
```

## Run Examples

The folder `examples` contains some examples to run `syft4fond`.

```
./syft4fond -d domain.pddl -p test1.pddl -g test1.ltlf # REALIZABLE
```

```
./syft4fond -d domain.pddl -p test2.pddl -g test2.ltlf # UNREALIZABLE
```

## Contacts

For any question, feedback, or suggestion, please reach to: parretti@diag.uniroma1.it
