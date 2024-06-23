import random
import time
import unittest
from amaxfactory.eosf import *
from amaxfactory.core.logger import Verbosity

verbosity([Verbosity.INFO, Verbosity.OUT])

MASTER = MasterAccount()
HOST = Account()

class Test(unittest.TestCase):
    def setUp(self) -> None:
        reset("/tmp/dex_spot.log")  

        global dex,master,fufiadmin,admin,amax_token,amax_mtoken,s1,s2,oracle,seer1,seer2
        publicKey = "AM7C17RqZXdVQZrMcYV5fYh8dG2CMmTwLcsf6ywtF6AbyhSnxCcW"
        privateKey = "5J8EncKYb4gzBK2TTp69LTZbttzqcRUnLeP1jj3hH6MykgUbWWk"
        fufiadmin = cleos.CreateKey(key_public=publicKey,key_private=privateKey)
        
        return super().setUp()

    def tearDown(self) -> None:
        stop()
        return super().tearDown()


    @staticmethod
    def getnumber():
        return random.randint(1,10000)
    
    def test_2(self):
        setup.set_nodeos_address("http://sh-amnod.vmi.amax.dev:18188")
        setup.set_test()
        dex = init.DEX_PERP("perp.usdtt2")

        
if __name__ == "__main__":
    unittest.main()