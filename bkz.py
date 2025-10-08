
import sys
sys.path.append("../ecdsa-lattice-attack-with-guessing/src/external/g6k") 
from fpylll import BKZ, LLL
from g6k import Siever
from g6k.algorithms.bkz import pump_n_jump_bkz_tour as bkz
from fpylll.tools.bkz_stats import dummy_tracer

def reduce_lattice_LLL(lattice):
        LLL.reduction(lattice.B)
        return
    
def reduce_lattice_BKZ(lattice, block_size):
    if block_size > len(lattice.signatures):
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
    