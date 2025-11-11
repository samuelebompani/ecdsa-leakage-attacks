# Ecdsa Leakage Attacks

## Getting started
### 1. Clone the repo
```bash
git clone git@github.com:samuelebompani/ecdsa-leakage-attacks.git
cd ecdsa-leakage-attacks
```
### 2. Clone G6K repo
```bash
git clone git@github.com:fplll/g6k.git
```
### 3. Change some parameters
To reproduce our experiments:
- In ```g6k/kernel/sieving.h``` set ```threads=64``` (optional) and ```MAX_SIEVING_DIM``` to ```512```.
- In ```g6k/configure.ac``` change
    ```c
    AC_ARG_WITH(max-sieving-dim,
            AS_HELP_STRING([--with-max-sieving-dim@<:@=DIM@:>@], [maximum supported sieving dimension [default=512]]),
            [max_sieving_dim=$withval],
            [max_sieving_dim=512])
    ```
    to
    
    ```c
    AC_ARG_WITH(max-sieving-dim,
            AS_HELP_STRING([--with-max-sieving-dim@<:@=DIM@:>@], [maximum supported sieving dimension [default=512]]),
            [max_sieving_dim=$withval],
            [max_sieving_dim=512])
    ```
- Set an high user open files limit:
    ```bash
    cd ecdsa-leakage-attacks/
    ulimit -n 4096
    ```
### 4. Create an .env
You just need to add

```txt
G6K_PATH="YourPathToG6KDirectory"
```
### 5. Create a virtual Environment
```bash
cd g6k
./bootstrap.sh [ -j # ]

#For every shell:
source ./activate
```
Now the environment is ready!

# Test
We will soon add some tests. For the moment, try running:
```bash
python3 toy.py -n 56 -l 5 --type "G6K" -a 1 -r 1
```
You should be able to retrieve the private key!