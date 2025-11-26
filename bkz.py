
import sys
sys.path.append("../g6k") 
from fpylll import BKZ, LLL
from g6k import Siever, SieverParams
from g6k.algorithms.bkz import pump_n_jump_bkz_tour as bkz
from fpylll.tools.bkz_stats import dummy_tracer
import math
import numpy as np

import traceback

def reduce_lattice_LLL(lattice):
        LLL.reduction(lattice.B)
        return
    
def reduce_lattice_BKZ(lattice, block_size):
    if block_size > len(lattice.signatures):
        print(f"[!] Block size {block_size} is too large for the number of signatures {len(lattice.signatures)}")
        return None
    params = BKZ.Param(
        block_size=block_size,
        strategies=BKZ.DEFAULT_STRATEGY,
        auto_abort=True)
    return BKZ.reduction(lattice.B, params)

def reduce_lattice_G6K(lattice, block_size, dim4free_par=0.3, extra_dim4free=4):
    if block_size > len(lattice.signatures):
        return None
    alg = bkz
    g6k = Siever(lattice.B)
    # dim4free heuristic ≈ 0.3 * β
    dim4free = lambda beta: max(10, int(dim4free_par * beta))
    try:
        a = alg(g6k, dummy_tracer, block_size, dim4free_fun=dim4free, extra_dim4free=min(extra_dim4free, len(lattice.signatures) - block_size + 2))
        return ("ok", a)
    except Exception as e:
        print(f"[!] BKZ reduction with block size {block_size} failed: {e}")
        return ("error", str(e))
    return lattice
    




###### |||                                              ||| ######
###### VVV ADDED FUNCTIONS FOR PREDICATE VERSION OF G6K VVV ######

def check_linear_predicate(vector, lattice):

    a= [ai for (ai, ti) in lattice.hnp_samples]
    t= [ti for (ai, ti) in lattice.hnp_samples]
    tau= lattice.tau
    leakage= lattice.leakage
    curve_order= lattice.curve.order  


    m= len(lattice.signatures) #dimension of vector -1 = number of signatures

    q = curve_order
    if lattice.leakage_type == "lsb":
        omega = q // (2 ** (leakage + 1))
    else:  #msb
        omega = (q // (2 ** (m -leakage + 1))) 
    
    last= vector[-1]
    alpha = None

    if len(a) != m or len(vector) != m + 1:
        return False, alpha

    if abs(last) != tau:
        return False, alpha


    t0 = t[0] % q
    try:
        inv_t0 = pow(t0, -1, q)
    except ValueError:
        return False, alpha

    
    
    if last == -tau:
        alpha = (inv_t0 * (a[0] + (vector[-2] + omega) % q)) % q
        for i in range(1,m+1):
            if (a[i] + (vector[i-1] + omega) % q) % q != (t[i] * alpha) % q:
                return False, None
    else:
        alpha = (inv_t0 * (a[0] + (-vector[-2] + omega) % q)) % q
        for i in range(1,m+1):
            if (a[i] - (vector[i-1] - omega) % q) % q != (t[i] * alpha) % q:
                return False, None
    

    return True, alpha



def multiply_left_PERSONALE(B, coeffs):
    """
    Multiplies the matrix B on the left by the vector coeffs.
    B: IntegerMatrix of size (n x m)
    coeffs: list of length n
    Returns: list of length m
    """
    nrows = B.nrows
    ncols = B.ncols
    if len(coeffs) != nrows:
        raise ValueError("Length of coeffs must be equal to number of rows in B")
    
    result = [0] * ncols
    for j in range(ncols):
        sum = 0
        for i in range(nrows):
            sum += int(coeffs[i]) * int(B[i, j])
        result[j] = sum
    return result


###### ∧∧∧ ADDED FUNCTIONS FOR PREDICATE VERSION OF G6K ∧∧∧ ######
###### |||                                              ||| ######




def scan_vectors_with_predicate(lattice,
                                g6k,
                                start_ctx,
                                end_ctx,
                                max_vectors: int = 100000):
    """
    Take the best vector in the sieve and check if they are the solution.

    max_vectors = a safty limit.
    """
    
    d = len(lattice.signatures) + 1
    B = g6k.M.B

    count = 0
    for sqnorm, proj_range, coeffs in g6k.best_lifts():

        if count >= max_vectors:
            break
        
      
        if len(coeffs) != d:
            print("error length coeffs")

        try:
            v = multiply_left_PERSONALE(B, coeffs)
        except Exception as e:
            print(f"Error multiplying left: {e}")
            traceback.print_exc()
            return False, None, None


        if len(v) != d:
            print("error length v")
        
        passed, alpha = check_linear_predicate(v, lattice)
        count += 1

        if passed:
            print("Eureka!")
            return True, v, alpha

    return False, None, None




def predicate_attack(lattice,
                     initial_dimension = 50, #dimension chosen in TCHES2023_2_20.pdf
                     max_loops_per_ell = 1,
                     dim4free = 3,
                     max_ell_iters = None,
                     verbose = False):

    d = len(lattice.signatures) + 1

    # Create params object with custom settings
    #params = SieverParams()
    #params.saturation_ratio = 0.2
    #params.saturation_radius = 5.0
 


    # Initialize G6K and sieve parameters
    g6k = Siever(lattice.B)#, params=params)


    tracer = dummy_tracer
    g6k.shrink_db(0)
    g6k.lll(0, d)
    g6k.update_gso(0, d)

    ell0 = max(0, d - initial_dimension)

    #stampa parametri
    #print(f"d {d}, initial_dimension {initial_dimension}, ell0 {ell0}")

    if max_ell_iters is None:
        max_ell_iters = ell0 + 1  # in teoria scendiamo fino a ell=0
    
    ell = ell0

    kappa = 0
    blocksize = initial_dimension

    if verbose:
        print(f"[+] Initializing progressive sieve from ell={ell0} down to 0, window = [{ell0} {d}]")

    g6k.initialize_local(kappa, ell, d, tracer) #ho tolto il tracer




    
    # Loop
    ell_steps = 0
    while ell >= 0 and ell_steps < max_ell_iters:

        if verbose:
            print(f"\n[+] Sieve at window [{ell}:{d}] (dim = {d-ell})")

        # Do a number of sieve loops at this ell
        for loop in range(max_loops_per_ell):

            #print(f" funziona loop {loop}")

            # Perform one sieve iteration
            try:
                g6k(alg="hk3")
                #g6k(alg="gauss")
                #g6k(alg="bgj1")
            except Exception as e:
                print(f"[!] Sieve iteration failed at ell={ell}, loop={loop}: {e}")
                continue
            
            # g6k.lll(ell, d)
            
            

            #print(f" funziona dopo {loop}")


            if verbose:
                print(f"    - sieve loop {loop+1}/{max_loops_per_ell} at ell={ell}")

            # At each iteration, scan the reduced vectors for the predicate
            
            found, v_solution, alpha = scan_vectors_with_predicate(lattice, g6k, ell, d)
           
            if found:
                if verbose:
                    print(f"[+] Predicate satisfied at ell={ell}. Found alpha = {alpha}")
                return True, alpha, v_solution

            #print("fine for")

        # If we reach here, no vector satisfied the predicate at this ell
        if ell == 0:
            break

        # Extend the window: [ell-1 : r]
        # extend_left() we pass from L[ell:r] to L[ell-1:r].
        g6k.extend_left()
        ell -= 1
        ell_steps += 1
        blocksize += 1


        if verbose:
            print(f"[+] Extended left: new window [{ell}:{d}]")






    if verbose:
        print("[!] Attack finished: predicate never matched.")
    return False, None, None




def reduce_lattice_G6K_predicate(lattice, block_size, dim4free_par=0.3, extra_dim4free=4):


    # dim4free heuristic ≈ 0.3 * β
    dim4free = lambda beta: max(10, int(dim4free_par * beta))


    d = len(lattice.signatures) + 1
    initial_dimension = 50 #dimension chosen in TCHES2023_2_20.pdf
    print(f"[*] G6K reduction with predicate and block size {block_size}")
    try:
        success, alpha, v_candidate =  predicate_attack(
            lattice= lattice,
            initial_dimension = initial_dimension,
            max_loops_per_ell=10,
            dim4free=0,
            max_ell_iters= None,
            verbose= True
        )
        print(f"va {success} {alpha} {v_candidate}")
        return success, alpha, v_candidate
    except Exception as e:
        print(f"[!] BKZ reduction with block size {block_size} failed: {e}")
        return ("error", False, str(e))

   