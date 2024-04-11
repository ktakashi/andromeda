(import (rnrs)
	(andromeda slip :10)
	(util bytevector)
	(srfi :64))

(test-begin "SLIP-0010")

(define (test-vector-test curve seed chains)
  (define chain (car chains))
  (let* ((mk (generate-master-key curve seed))
	 (pk (derive-public-key curve mk)))
    (test-equal "chain code" (hex-string->bytevector (car chain))
		(deriveable-key-c mk))
    (test-equal "private key" (hex-string->bytevector (cadr chain))
		(deriveable-key-k mk))
    (test-equal "public key" (hex-string->bytevector (caddr chain)) pk)
		
    (fold-left
     (lambda (k chain)
       (let* ((priv (derive-private-key curve k (cadddr chain)))
	      (pubk (derive-public-key curve priv)))
	 (test-equal "chain code" (hex-string->bytevector (car chain))
		     (deriveable-key-c priv))
	 (test-equal "private key" (hex-string->bytevector (cadr chain))
		     (deriveable-key-k priv))
	 (test-equal "public key" (hex-string->bytevector (caddr chain)) pubk)
	 priv))
     mk
     (cdr chains))))

(test-vector-test (slip-curve secp256k1)
 (hex-string->bytevector "000102030405060708090a0b0c0d0e0f")
 `(("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
    "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
    "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
    #f)
   ("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
    "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
    "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"
    ,(hardened-child-key 0)
    )
   ("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"
    "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
    "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"
    1
    )))
(test-end)
