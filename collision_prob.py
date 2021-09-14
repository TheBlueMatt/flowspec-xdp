# Approximate collisions in an N-bucket hash table
# Using suggested approximate formula from https://stats.stackexchange.com/questions/1308/extending-the-birthday-paradox-to-more-than-2-people

import math

def poisson_pdf(avg, k):
	return (avg ** k) / (math.factorial(k) * math.e**avg)

def poisson_cdf(avg, k):
	# Lazy version of inclusive cdf from 0 through k
	it = 0
	for i in range(0, k+1):
		it += poisson_pdf(avg, i)
	return it

def poisson_pow(n, b, k):
	if k == 0:
		return poisson_cdf(n/b, 0)**b
	sub = 0
	for i in range(0, k):
		sub += poisson_pow(n, b, i)
	return poisson_cdf(n/b, k)**b - sub

def inv_poisson_pow(n, b, k):
	it = 0
	# This loop is equivalent to the below two-step:
	#for i in range(1, k):
	#	it += poisson_pow(n, b, i)
	it -= poisson_cdf(n/b, 0)**b
	it += poisson_cdf(n/b, k-1)**b
	return 1 - it

def print_entry(e, t, b):
	# We have t/b buckets, and want the probability that no bucket has >= b+1 entries
	print("\t%ldK entries, %ld-buckets: %.20f" % (e/1000, b, inv_poisson_pow(e, t/b, b+1)))

# Base cases which can be compared with WolframAlpha
# Note that we have to multiply by b to undo the division in print_entry
# https://www.wolframalpha.com/input/?i=birthday+problem+calculator&assumption=%7B%22F%22%2C+%22BirthdayProblem%22%2C+%22pbds%22%7D+-%3E%2220000%22&assumption=%7B%22F%22%2C+%22BirthdayProblem%22%2C+%22n%22%7D+-%3E%22300%22&assumption=%22FSelect%22+-%3E+%7B%7B%22BirthdayProblem%22%7D%7D
#print_entry(300, 20000, 1)
#print_entry(300, 20000*2, 2)

print("Table and bucket sizes mapped to rough element count which has a 1% bucket-overflow probability")
print("Note that we currently have a hard-coded bucket size of 16 elements")
print()

print("128K table * 16 bytes = %dMiB." % (128*16/1024))
print_entry(4000, 128*1024, 4)
print_entry(15000, 128*1024, 8)
print_entry(33000, 128*1024, 16)
print_entry(53000, 128*1024, 32)

print("256K table * 16 bytes = %dMiB." % (256*16/1024))
print_entry(7000, 256*1024, 4)
print_entry(28000, 256*1024, 8)
print_entry(63000, 256*1024, 16)
print_entry(104000, 256*1024, 32)

print("512K table * 16 bytes = %dMiB." % (512*16/1024))
print_entry(13000, 512*1024, 4)
print_entry(52000, 512*1024, 8)
print_entry(119000, 512*1024, 16)
print_entry(200000, 512*1024, 32)

print("1M table * 16 bytes = %dMiB." % (1024*16/1024))
print_entry(23000, 1024*1024, 4)
print_entry(95000, 1024*1024, 8)
print_entry(227000, 1024*1024, 16)
print_entry(387000, 1024*1024, 32)

print("2M table * 16 bytes = %dMiB." % (2*1024*16/1024))
print_entry(40000, 2*1024*1024, 4)
print_entry(175000, 2*1024*1024, 8)
print_entry(431000, 2*1024*1024, 16)
print_entry(749000, 2*1024*1024, 32)
