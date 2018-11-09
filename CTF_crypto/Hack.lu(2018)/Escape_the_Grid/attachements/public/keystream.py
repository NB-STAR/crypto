from flag import flag
from matrix import matrix
from math import floor, factorial
from binascii import hexlify

import numpy as np

n = 385
rounds = 5
offset = 2432902008176639000

key = np.random.randint( 0, 2, size=n )


def mul_state(x1, x2, n):
	result = [-1] * n
	for i in range(n):
		result[i] = x1[i] * x2[i]
	return result


def scalar_prod(x1, x2, n):
	mul = mul_vec(x1, x2, n)
	result = 0

	for _ in range(n):
		result ^= (mul & 1)
		mul >>= 1

	return result


def rotate(x, r, n):
	result = []

	for i in range(n):
		result.append( x[(r+i) % n] )

	return result


def add_state(x1, x2, n):
	result = []
	for i in range(n):
		result.append( x1[i] ^ x2[i] ) 
	return result


def s_layer(state, n):
	result = mul_state( rotate(state, 1, n), rotate(state, 2, n), n )
	result = add_state( rotate(state, 2, n), result, n )
	return add_state(result, state, n)


def matrix_mul(state, matrix, n):
	result = []

	for i in range(n):
		bit = 0
		for k in range(n):
			bit ^= matrix[i][k] & state[k]
		result.append(bit)

	return result


def permutate_matrix(matrix, perm, n):
	result = [ [0]*n for _ in range(n) ]

	for i in range(n):
		for k in range(n):
			result[k][perm[i]] = matrix[k][i]

	return result


def get_permutation(i, n):
	elements = range(n)
	permutation = []
	for k in range(n-1):
		i = i % factorial(n-k)
		e = int(floor(i / factorial(n -k - 1) ))
		permutation.append( elements[e] )
		del elements[e]
	return permutation + elements


def rasta_standard(key, rounds, n, i, matrix):
	cnt = i % factorial(n)
	cnt = (cnt + offset)  % factorial(n)
	i = i / factorial(n)

	lin_layer = permutate_matrix(matrix, get_permutation(cnt, n), n)
	state = matrix_mul(key, lin_layer, n)

	for _ in range(rounds):
		state = s_layer(state, n)
		
		cnt += i % factorial(n)
		i = i / factorial(n)
		lin_layer = permutate_matrix(matrix, get_permutation(cnt, n), n)
		state = matrix_mul(state, lin_layer, n)

	state = add_state(state, key, n)
	return state


def list_to_num(l):
	num = 0L
	for i in l:
		num <<= 1
		num += i
	return num


def generate_keystream_block(i):
	block = rasta_standard(key, rounds, n, i, matrix)
	return hex( list_to_num( block ) )


def generate_challenge():
	return hex( list_to_num(key) ^ int( hexlify(flag), 16) )