import urllib2
import sys
import os
import logging
import shelve

from crypto_primitives import strxor

logger = logging.getLogger("padding_oracle")
FORMAT = '%(asctime)-15s %(message)s'
FILENAME = "memento"

def config(p_filename, log_level):
    logging.basicConfig(format=FORMAT, filename=p_filename, level=log_level)

TARGET = 'http://crypto-class.appspot.com/po?er='
BLOCK_SIZE_IN_BYTES = 16
RAW_ZERO_BLOCK = "".join(chr(x) for x in [0] * BLOCK_SIZE_IN_BYTES)

class Memento:
    pass

class Persistence:
    def __init__(self, filename, clear):
        if clear and os.isfile(filename):
            os.remove(filename)
        self.filename = filename

    def save(self, memento):
        with open(self.filename, "wbc") as f:
            f.truncate()
            pickle.dump(memento, f)

    def load(self):
        with open(self.filename, "wbc") as f:
            memento = pickle.load(f)

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

def create_xoring_pattern(block_size, byte_value_and_count, guess, a_string):
    padding_numerical = [0] * (block_size - byte_value_and_count)
    padding_numerical = padding_numerical + [byte_value_and_count^guess]
    padding_numerical = padding_numerical + [byte_value_and_count] * (byte_value_and_count - 1)

    padding = "".join(chr(x) for x in padding_numerical)
    
    return strxor(padding, a_string)

def create_request(prepending, block_to_try, raw_xoring_pattern):
    return "".join([strxor(prepending, raw_xoring_pattern), block_to_try]).encode("hex")

def update_string(which_byte, what_value, previous_value):
    return previous_value[0:which_byte] + chr(what_value) + previous_value[which_byte + 1:] 


def split_cbc_to_blocks( raw_cbc_ciphertext ):
    blocks = []
    for i in xrange(len(raw_cbc_ciphertext) / BLOCK_SIZE_IN_BYTES):
        blocks.append(raw_cbc_ciphertext[i*BLOCK_SIZE_IN_BYTES:(i+1)*BLOCK_SIZE_IN_BYTES])
    return blocks


class StatefulAECruncher:
    def __init__(self, persistence, cbc_ciphertext_in_hex):
        logger.debug("Init from scratch, setting persistence layer")
        self.persistence = persistence
        
        if cbc_ciphertext_in_hex:
            self.feed(cbc_ciphertext_in_hex)
        else:
            restart()
        
    def feed(self, cbc_ciphertext_in_hex):
        self.cbc = cbc_ciphertext_in_hex
        self.block = 1
        self.block_iterator = None
        self.intermediate_results = []
        self.restart = False


    def restart(self):
        logger.debug("Init from persistence layer")
        memento=self.persistence.load()
        self.cbc = memento.cbc
        self.block = memento.block
        
        if memento.iterator_memento is None:
            self.block_iterator = None
        else:
            self.block_iterator = BlockIterator.create_from_memento(self, iterator_memento)
        self.intermediate_results = memento.results
        self.restart = True

    def get_memento(self):
        memento = Memento()
        if self.block_iterator:
            memento.iterator_memento = self.block_iterator.get_memento()
        else:
            memento.iterator_memento = None
        memento.cbc = self.cbc
        memento.block = self.block
        memento.results = self.intermediate_results
        return memento

    def save(self):
        memento = self.get_memento()
        self.persistence.save(memento)

    def process(self, po):
        blocks = split_cbc_to_blocks( self.cbc.decode("hex") )
        
        while self.block < len(blocks):
            if not self.restart:
                self.block_iterator = BlockIterator.create_from_blocks(self, blocks[self.block -1 ], blocks[self.block])
            else:
                self.restart = False
        
            decoded_block = self.block_iterator.process(po)
            self.block = self.block + 1
            self.intermediate_results.append(decoded_block)
            self.block_iterator = None
            self.save()
        return "".join(self.intermediate_results)


class BlockIterator:
    @staticmethod
    def create_from_blocks(parent, block_preceding, block_to_decipher):
        obj = BlockIterator(parent)
        obj.make(block_preceding, block_to_decipher)
        return obj

    def create_from_memento(parent, memento):
        obj = BlockIterator(parent)
        obj.load(memento)
        return obj

    def __init__(self, parent):
        self.parent = parent

    def make(self, block_preceding, block_to_decipher):
        self.block_preceding = block_preceding
        self.block_to_decipher = block_to_decipher
        self.current_byte_offset_from_end = 0
        self.current_byte_value = 0
        self.found_so_far = RAW_ZERO_BLOCK
        self.restart = False

    def load(self, memento):
        self.block_preceding = memento.block_preceding
        self.block_to_decipher = memento.block_to_decipher
        self.current_byte_offset_from_end = memento.offset
        self.current_byte_value = memento.value
        self.found_so_far = memento.found_so_far
        self.restart = True
        
    def get_memento(self):
        memento = Memento()
        memento.block_preceding = self.block_preceding
        memento.block_to_decipher = self.block_to_decipher
        memento.offset = self.current_byte_offset_from_end
        memento.value = self.current_byte_value
        memento.found_so_far = self.found_so_far
        return memento

    def process(self, po):
        while self.current_byte_offset_from_end < BLOCK_SIZE_IN_BYTES:
            logger.debug("Processing {} block, byte  {}".format(self.block_to_decipher.encode("hex"), 
                BLOCK_SIZE_IN_BYTES - self.current_byte_offset_from_end))
            if not self.restart:
                self.current_byte_value = 0
            else:
                self.restart = True

            while self.current_byte_value < 256:
                logger.debug("Trying byte value: {}".format(self.current_byte_value))
                raw_xoring_pattern = create_xoring_pattern(BLOCK_SIZE_IN_BYTES, 
                    self.current_byte_offset_from_end + 1, 
                    self.current_byte_value, 
                    self.found_so_far)
                logger.debug("Xoring pattern %s" % raw_xoring_pattern.encode("hex"))
                request = create_request(self.block_preceding, self.block_to_decipher, raw_xoring_pattern)
                logger.debug("Request: %s" % request )
                if po.query(request):
                    self.found_so_far = update_string(BLOCK_SIZE_IN_BYTES - self.current_byte_offset_from_end,
                        self.current_byte_value, self.found_so_far)
                    logger.debug("Found last byte of a block! %s" % self.found_so_far.encode("hex"))
                    self.current_byte_value = 0
                    self.parent.save()
                    break
                self.current_byte_value = self.current_byte_value + 1
                self.parent.save()
                
            else:
                raise ValueError("no byte found for position")
            self.current_byte_offset_from_end = self.current_byte_offset_from_end + 1



if __name__ == "__main__":
    import time
    config("padding", logging.DEBUG)
    persistence = Persistence(FILENAME, False)
    if os.path.isfile(FILENAME):
        logging.debug("Found filename %s" % FILENAME)
        cruncher = StatefulAECruncher(persistence, None)
        cruncher.restart()
    else:
        cruncher = StatefulAECruncher(persistence, "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4")
    po = PaddingOracle()
    print cruncher.process(po)