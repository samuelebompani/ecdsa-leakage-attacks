
import sys
sys.path.append("../ecdsa-lattice-attack-with-guessing/src/external/g6k") 
from fpylll import BKZ
from g6k import Siever
from g6k.algorithms.bkz import pump_n_jump_bkz_tour as bkz
from fpylll.tools.bkz_stats import dummy_tracer

    
def reduce_lattice_BKZ(lattice, block_size):
    if block_size > len(lattice.signatures):
        return None
    params = BKZ.Param(
        block_size=block_size,
        strategies=BKZ.DEFAULT_STRATEGY,
        auto_abort=True)
    return BKZ.reduction(lattice.B, params)

def reduce_lattice_G6K(lattice, block_size):
    if block_size > len(lattice.signatures):
        return None
    alg = bkz
    g6k = Siever(lattice.B)
    # dim4free heuristic ≈ 0.3 * β
    dim4free = lambda beta: max(10, int(0.3 * beta))
    return alg(g6k, dummy_tracer, block_size, dim4free_fun=dim4free)