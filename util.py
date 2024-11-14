import string
import random
import itertools
import math

from operator import sub

_POOL = string.ascii_uppercase + string.ascii_lowercase + string.digits
def generate_fill(length):
    return ''.join(random.choice(_POOL) for _ in range(length)) 

def sum_to_n(n):
    'Generate the series of +ve integer lists which sum to a +ve integer, n.'
    b, mid, e = [0], list(range(1, n)), [n]
    splits = (d for i in range(n) for d in itertools.combinations(mid, i)) 
    foo = (list(map(sub, itertools.chain(s, e), itertools.chain(b, s))) for s in splits)

    pows = [pow(2, x) for x in range(0, n + 1)]
    possible = []
    for x in foo:
        used = []
        success = True
        for y in x:
            if(y not in pows): 
                success = False
                break
            if(y in used): 
                success = False
                break
            else: used.append(y)

        x.sort()
        if(x not in possible and success): possible.append(x)
    return possible
