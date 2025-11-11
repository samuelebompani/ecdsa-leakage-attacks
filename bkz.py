
import sys
sys.path.append("../g6k") 
from fpylll import BKZ, LLL
from g6k import Siever
from g6k.algorithms.bkz import pump_n_jump_bkz_tour as bkz
from fpylll.tools.bkz_stats import dummy_tracer
import math

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
    





def predicate(vector, tau, leakage, curve_order, a, t):

    q = curve_order
    omega = q // (1 << (leakage + 1))  #VALE SOLO PER LSB !!!!!!!!!!!!!!!!!!!!!!!!!111 per msb usa n-1
    m= len(t)
    last= int(vector[-1])


    if abs(last) != tau:
        return False

    if last == -tau:
        alpha = pow(t[0],-1,q) * (vector[-2] + omega + a[0]) % q
        for i in range(m):
            lhs = (a[i] + (vector[i-1] + omega)) % q
            rhs = (t[i] * alpha) % q
            if lhs != rhs:
                return False
    elif vector[-1] == tau:
        alpha = pow(t[0],-1,q) * (omega - vector[-2] + a[0]) % q
        for i in range(m):
            lhs = (a[i] - (vector[i-1] - omega)) % q
            rhs = (t[i] * alpha) % q
            if lhs != rhs:
                return False

    return True



def reduce_lattice_G6K_predicate(lattice, block_size, a, t, leakage, dim4free_par=0.3, extra_dim4free=4):
    if block_size > len(lattice.signatures):
        return None
    alg = bkz
    g6k = Siever(lattice.B)
    # dim4free heuristic ≈ 0.3 * β
    dim4free = lambda beta: max(10, int(dim4free_par * beta))

    pred_fn = lambda vector: predicate(
        vector,
        tau= ( lattice.curve.order // 2**(leakage +1) ) // math.sqrt(3),
        leakage=leakage,
        curve_order=lattice.curve.order,    
        a=a,
        t=t
    )

    try:
        a = alg(g6k, dummy_tracer, block_size, predicate=pred_fn, dim4free_fun=dim4free, extra_dim4free=min(extra_dim4free, len(lattice.signatures) - block_size + 2))
        return ("ok", a)
    except Exception as e:
        print(f"[!] BKZ reduction with block size {block_size} failed: {e}")
        return ("error", str(e))
    return lattice
        