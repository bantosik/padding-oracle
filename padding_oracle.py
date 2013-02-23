import urllib2
import sys
import logging
from crypto_primitives import strxor

logger = logging.getLogger("padding_oracle")
FORMAT = '%(asctime)-15s %(message)s'

def config(p_filename, log_level):
    logging.basicConfig(format=FORMAT, filename=p_filename, level=log_level)

TARGET = 'http://crypto-class.appspot.com/po?er='
BLOCK_SIZE_IN_BYTES = 16
RAW_ZERO_BLOCK = "".join(chr(x) for x in [0] * BLOCK_SIZE_IN_BYTES)
#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
class PaddingOracle(object):
    def query(self, q):
        target = TARGET + urllib2.quote(q)    # Create query URL
        req = urllib2.Request(target)         # Send HTTP request to server
        try:
            f = urllib2.urlopen(req)          # Wait for response
        except urllib2.HTTPError, e:          
            logger.debug("We got: %d" % e.code)       # Print response code
            if e.code == 404:
                return True # good padding
            return False # bad padding

def get_message_from_cbc_with_ae( cbc_ciphertext_in_hex, po ):
    blocks = split_cbc_to_blocks( cbc_ciphertext_in_hex.decode("hex") )
    result = []
    for i in xrange(1, len(blocks)):
        result.append(decode_block(blocks, i, po))

def create_xoring_pattern(block_size, byte_value_and_count, guess, a_string):
    padding_numerical = [0] * (block_size - byte_value_and_count)
    padding_numerical = padding_numerical + [byte_value_and_count^guess]
    padding_numerical = padding_numerical + [byte_value_and_count] * (byte_value_and_count - 1)

    padding = "".join(chr(x) for x in padding_numerical)
    
    return strxor(padding, a_string)

def create_request(blocks, which, raw_xoring_pattern):
    prepending = blocks[which - 1]
    block_to_try = blocks[which]
    return "".join(blocks[0:which-1] + [strxor(prepending, raw_xoring_pattern), block_to_try]).encode("hex")

def decode_block(blocks, which, po):
    found_so_far = RAW_ZERO_BLOCK

    for i in xrange(1, BLOCK_SIZE_IN_BYTES):
        logger.debug("Processing {} block, byte {}".format(which, BLOCK_SIZE_IN_BYTES - i))
        for j in xrange(256):    
            logger.debug("Trying byte value: {}".format(j))
            raw_xoring_pattern = create_xoring_pattern(BLOCK_SIZE_IN_BYTES, i, j, found_so_far)
            logger.debug("Xoring pattern %s" % raw_xoring_pattern.encode("hex"))
            request = create_request(blocks, which, raw_xoring_pattern)
            logger.debug("Request: %s" % request )
            if po.query(request):
                found_so_far = update_string(BLOCK_SIZE_IN_BYTES - i,j,found_so_far)
                logger.debug("Found last byte of a block! %s" % found_so_far.encode("hex"))
                break
        else:
            raise ValueError("no byte found for position {} in block {}".format(i, block_to_try.encode("hex")))

def update_string(which_byte, what_value, previous_value):
    return previous_value[0:which_byte] + chr(what_value) + previous_value[which_byte + 1:] 


def split_cbc_to_blocks( raw_cbc_ciphertext ):
    blocks = []
    for i in xrange(len(raw_cbc_ciphertext) / BLOCK_SIZE_IN_BYTES):
        blocks.append(raw_cbc_ciphertext[i*BLOCK_SIZE_IN_BYTES:(i+1)*BLOCK_SIZE_IN_BYTES])
    return blocks

if __name__ == "__main__":
    import time
    config("padding", logging.DEBUG)

    po = PaddingOracle()
    print get_message_from_cbc_with_ae( 
        "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4", 
        po )