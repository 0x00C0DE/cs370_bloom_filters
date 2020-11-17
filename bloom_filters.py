# -*- coding: utf-8 -*-
#Braden Lee
import base64
import os
import cryptography
from cryptography import utils
from cryptography.hazmat.primitives.ciphers import (
    BlockCipherAlgorithm,
    CipherAlgorithm,
)
from cryptography.hazmat.primitives.ciphers.modes import ModeWithNonce
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.backends import default_backend
import codecs
from binascii import hexlify, b2a_base64, unhexlify, a2b_base64, b2a_hex, a2b_hex
from cryptography.hazmat.primitives import hashes
import hashlib
import random
import sys
import time

#backend needed to run
backend = default_backend()

#opens file to read from
with open (sys.argv[1], 'r') as myfile:
	
	#reads each line split for the word
	Tempkey = myfile.read().splitlines()
	
	#creates a list of objects to test(ie key)
	Tempkey = [ x.strip() for x in Tempkey]
	#print("len tempkey:", len(Tempkey))
		
	# m = ((623518 * log(0.1)) / log(1 / pow(2, log(2)))) = 2988228 bit array size

	#2988228 0.1 (false positive rate) 
	#2088681 0.2
	#5976456 0.01

	#hash bloom filter 1	
	bit_vect1 = [0] * 2988288

	#hash bloom filter 2
	bit_vect2 = [0] * 2988288
	
	print("starting bloom filter process...")

	#for each line
	for kkey in Tempkey:
		TempHash = str(kkey)
		TempHash = ' '.join(format(ord(x), 'b') for x in TempHash)		

		#bloom filter 1 setting bad passwords
		b1_h1 = hashes.Hash(hashes.SHA224(), backend=backend)
		b1_h1.update(TempHash.encode())
		b1_h1_hval = b1_h1.finalize()
		b1_h1_hval = hexlify(b1_h1_hval)
		b1_h1_hval = int(b1_h1_hval, 16)
	
		#calculated index for each bloomfilter
		b1_h1_hval = int(b1_h1_hval) % (len(bit_vect1))

		#set corresponding bloom filter index to 1
		bit_vect1[b1_h1_hval] = 1

		b1_h2 = hashes.Hash(hashes.SHA256(), backend=backend)
                b1_h2.update(TempHash.encode())
                b1_h2_hval = b1_h2.finalize()
                b1_h2_hval = hexlify(b1_h2_hval)
                b1_h2_hval = int(b1_h2_hval, 16)
                b1_h2_hval = int(b1_h2_hval) % (len(bit_vect1))

		bit_vect1[b1_h2_hval] = 1

		b1_h3 = hashes.Hash(hashes.SHA384(), backend=backend)
                b1_h3.update(TempHash.encode())
                b1_h3_hval = b1_h3.finalize()
                b1_h3_hval = hexlify(b1_h3_hval)
                b1_h3_hval = int(b1_h3_hval, 16)
                b1_h3_hval = int(b1_h3_hval) % (len(bit_vect1))

		bit_vect1[b1_h3_hval] = 1
	
		#bloom filter 2 setting bad passwords	
		b1_h4 = hashes.Hash(hashes.SHA3_224(), backend=backend)
                b1_h4.update(TempHash.encode())
                b1_h4_hval = b1_h4.finalize()
                b1_h4_hval = hexlify(b1_h4_hval)
                b1_h4_hval = int(b1_h4_hval, 16)
                
		#calculated index for each bloomfilter
		b1_h4_hval = int(b1_h4_hval) % (len(bit_vect2))
		
		#set corresponding bloom filter index to 1
		bit_vect2[b1_h4_hval] = 1

		b1_h5 = hashes.Hash(hashes.SHA3_256(), backend=backend)
                b1_h5.update(TempHash.encode())
                b1_h5_hval = b1_h5.finalize()
                b1_h5_hval = hexlify(b1_h5_hval)
                b1_h5_hval = int(b1_h5_hval, 16)
                b1_h5_hval = int(b1_h5_hval) % (len(bit_vect2))

		bit_vect2[b1_h5_hval] = 1	

		b1_h6 = hashes.Hash(hashes.SHA3_384(), backend=backend)
                b1_h6.update(TempHash.encode())
                b1_h6_hval = b1_h6.finalize()
                b1_h6_hval = hexlify(b1_h6_hval)
                b1_h6_hval = int(b1_h6_hval, 16)
                b1_h6_hval = int(b1_h6_hval) % (len(bit_vect2))

		bit_vect2[b1_h6_hval] = 1

		b1_h7 = hashes.Hash(hashes.SHA3_512(), backend=backend)
                b1_h7.update(TempHash.encode())
                b1_h7_hval = b1_h7.finalize()
                b1_h7_hval = hexlify(b1_h7_hval)
                b1_h7_hval = int(b1_h7_hval, 16)
                b1_h7_hval = int(b1_h7_hval) % (len(bit_vect2))

		bit_vect2[b1_h7_hval] = 1

                b1_h8 = hashes.Hash(hashes.MD5(), backend=backend)
		b1_h8.update(TempHash.encode())
                b1_h8_hval = b1_h8.finalize()
                b1_h8_hval = hexlify(b1_h8_hval)
                b1_h8_hval = int(b1_h8_hval, 16)
                b1_h8_hval = int(b1_h8_hval) % (len(bit_vect2))

		bit_vect2[b1_h8_hval] = 1
		

print("ok done hashing all the dictionary.txt words")


print("ok done appending/making bloom filter 3h and 5h")

secondFile = open(sys.argv[2]) 

#skips first line since it's only the number of lines in the file
next(secondFile)

for samp_L in secondFile:

	TempLine = samp_L.splitlines()
	TempLine = [ x.strip() for x in TempLine ]

	for eachL in TempLine:
		pasHash = str(eachL)
		pasHash = ' '.join(format(ord(x), 'b') for x in pasHash)
		
		#checks for bloom filter 1
		pasH1 = hashes.Hash(hashes.SHA224(), backend=backend)
		pasH1.update(pasHash.encode())
		pasH1_hval = pasH1.finalize()
		pasH1_hval = hexlify(pasH1_hval)
		pasH1_hval = int(pasH1_hval, 16)

		#calculated index for each bloom filter for the password to be checked
		pasH1_hval = int(pasH1_hval) % 	(len(bit_vect1))

		#checks if the index is set to 1 in the bloom filter
		out1_check1 = bit_vect1[pasH1_hval]

		pasH2 = hashes.Hash(hashes.SHA256(), backend=backend)
                pasH2.update(pasHash.encode())
                pasH2_hval = pasH2.finalize()
                pasH2_hval = hexlify(pasH2_hval)
                pasH2_hval = int(pasH2_hval, 16)
                pasH2_hval = int(pasH2_hval) %  (len(bit_vect1))

                out1_check2 = bit_vect1[pasH2_hval]

		pasH3 = hashes.Hash(hashes.SHA384(), backend=backend)
                pasH3.update(pasHash.encode())
                pasH3_hval = pasH3.finalize()
                pasH3_hval = hexlify(pasH3_hval)
                pasH3_hval = int(pasH3_hval, 16)
                pasH3_hval = int(pasH3_hval) %  (len(bit_vect1))

                out1_check3 = bit_vect1[pasH3_hval]

		#check for bloom filter 2
		pasH4 = hashes.Hash(hashes.SHA3_224(), backend=backend)
                pasH4.update(pasHash.encode())
                pasH4_hval = pasH4.finalize()
                pasH4_hval = hexlify(pasH4_hval)
                pasH4_hval = int(pasH4_hval, 16)
		
		#calculated index for each bloom filter for the password to be checked
                pasH4_hval = int(pasH4_hval) %  (len(bit_vect2))
		
		#checks if the index is set to 1 in the bloom filter
                out2_check4 = bit_vect2[pasH4_hval]

		pasH5 = hashes.Hash(hashes.SHA3_256(), backend=backend)
                pasH5.update(pasHash.encode())
                pasH5_hval = pasH5.finalize()
                pasH5_hval = hexlify(pasH5_hval)
                pasH5_hval = int(pasH5_hval, 16)
                pasH5_hval = int(pasH5_hval) %  (len(bit_vect2))

                out2_check5 = bit_vect2[pasH5_hval]

		pasH6 = hashes.Hash(hashes.SHA3_384(), backend=backend)
                pasH6.update(pasHash.encode())
                pasH6_hval = pasH6.finalize()
                pasH6_hval = hexlify(pasH6_hval)
                pasH6_hval = int(pasH6_hval, 16)
                pasH6_hval = int(pasH6_hval) %  (len(bit_vect2))

                out2_check6 = bit_vect2[pasH6_hval]

		pasH7 = hashes.Hash(hashes.SHA3_512(), backend=backend)
                pasH7.update(pasHash.encode())
                pasH7_hval = pasH7.finalize()
                pasH7_hval = hexlify(pasH7_hval)
                pasH7_hval = int(pasH7_hval, 16)
                pasH7_hval = int(pasH7_hval) %  (len(bit_vect2))

                out2_check7 = bit_vect2[pasH7_hval]

                pasH8 = hashes.Hash(hashes.MD5(), backend=backend)
		pasH8.update(pasHash.encode())
                pasH8_hval = pasH8.finalize()
                pasH8_hval = hexlify(pasH8_hval)
                pasH8_hval = int(pasH8_hval, 16)
                pasH8_hval = int(pasH8_hval) %  (len(bit_vect2))

                out2_check8 = bit_vect2[pasH8_hval]
	
		#condition check/write to output3.txt
		#checking bloom filter1
		bloom_filter1_start = time.time()

		if ((out1_check1 == 1) and (out1_check2 == 1) and (out1_check3 == 1)):
			output3_file = open(sys.argv[3], "a")
			output3_file.write("maybe\n")
			#output3_file.write(" ")	
			output3_file.close()
		
		else:
			output3_file = open(sys.argv[3], "a")
			output3_file.write("no\n")
			#output3_file.write(" ")
			output3_file.close()

		bloom_filter1_end = time.time()
		bloom_filter1_timetaken = bloom_filter1_end - bloom_filter1_start
		print("time taken to check 1 pass in bloom filter 1:", bloom_filter1_timetaken)
		
		#condition check/write to output5.txt
		#checking bloom filter2
		bloom_filter2_start = time.time()
	
		if ((out2_check4 == 1) and (out2_check5 == 1) and (out2_check6 == 1) and (out2_check7 == 1) and (out2_check8 == 1)):
			output5_file = open(sys.argv[4], "a")
                        output5_file.write("maybe\n")
			#output5_file.write(" ")
                        output5_file.close()
		else:
			output5_file = open(sys.argv[4], "a")
                        output5_file.write("no\n")
			#output5_file.write(" ")
                        output5_file.close()	

		bloom_filter2_end = time.time()
		bloom_filter2_timetaken = bloom_filter2_end - bloom_filter2_start
                print("time taken to check 1 pass in bloom filter 2:", bloom_filter2_timetaken)
		

print("ok done hashing all the sample input passwords")						

print("ok done testing everything")
		
