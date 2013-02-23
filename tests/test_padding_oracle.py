from unittest import TestCase
from crypto_primitives import strxorhex
import unittest

import padding_oracle

test_string = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4"

class TestPaddingOracle(TestCase):
	def test_apprioprate_length_split_cbc_to_blocks(self):
		s = test_string.decode("hex")
		t = padding_oracle.split_cbc_to_blocks(s)
		self.assertEqual(len(t), 4)

	def test_split_cbc_to_blocks(self):
		 s = test_string.decode("hex")
		 t = padding_oracle.split_cbc_to_blocks(s)
		 print [x.encode("hex") for x in t]
		 self.assertEqual(t[1].encode("hex"), "58b1ffb4210a580f748b4ac714c001bd" ,
        msg="first block should be get from test string")

	def test_create_xoring_pattern(self):
		t = "000102030405060708090a0b0c0d0e0f"
		guess = 2
		padding = padding_oracle.create_xoring_pattern(padding_oracle.BLOCK_SIZE_IN_BYTES, 1, guess, t.decode("hex"))
		self.assertEqual("000102030405060708090a0b0c0d0e0c", padding.encode("hex"),
			msg="for value one last byte should change. We have: {}".format(padding.encode("hex")))

	
	def test_create_request(self):
		xoring_pattern = "ffffffffffffffffffffffffffffffff".decode("hex")
		block = []
		block.append("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f".decode("hex"))
		block.append("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f".decode("hex"))
		block.append("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f".decode("hex"))
		block.append("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".decode("hex"))
		
		request = padding_oracle.create_request(block, 2, xoring_pattern)
		self.assertEqual(request, 
			"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0ff0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f00f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", 
			msg="Middle block should negate and block after which should be removed. We have: {}".format(request.encode("hex")))
    
    # def test_decode_block(self):
    # 	key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    # 	block_to_decrypt = "0102030405060708090a0b0c0d0e0f".decode("hex")



if __name__=="__main__":
	unittest.main()
