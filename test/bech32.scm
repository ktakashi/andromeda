#!read-macro=sagittarius/bv-string
(import (rnrs)
	(andromeda bip bech32)
	(util bytevector)
	(srfi :64))

(test-begin "Bech32")

(define ((test-bech32 type) bech)
  (let-values (((hrp _ dspec) (bech32-decode bech)))
    (let* ((p (bytevector-index-right bech (char->integer #\1)))
	   (hrp2 (bytevector-copy bech 0 (+ p 1)))
	   (v (bitwise-xor (bytevector-u8-ref bech (+ p 1)) 1))
	   (data (bytevector-copy bech (+ p 2))))
      (test-error `(,type "Invalid Bech (reconstructed)")
		  (bech32-decode (bytevector-append hrp2
						    (make-bytevector 1 v)
						    data))))))
(for-each (test-bech32 'bech32)
	  '(#;#*"A12UEL5L"
	    #*"a12uel5l"
	    #*"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs"
	    #*"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw"
	    #*"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j"
	    #*"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"
	    #*"?1ezyfcl"))
(for-each (test-bech32 'bech32m)
	  '(#;#*"A1LQFN3A"
	    #*"a1lqfn3a"
	    #*"an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6"
	    #*"abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx"
	    #*"11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8"
	    #*"split1checkupstagehandshakeupstreamerranterredcaperredlc445v"
	    #*"?1v759aa"))
	  

(define ((test-invalid-bech32 type) bech)
  (test-error `(,type "Invalid checksum") (bech32-decode bech)))

(for-each (test-invalid-bech32 'bech32)
	  '(#*" 1nwldj5"          ;; HRP character out of range
	    #*"\x7F;1axkwrx"  ;; HRP character out of range
	    #*"\x80;1eym55h"  ;; HRP character out of range
	    ;; overall max length exceeded
	    #*"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx"
	    #*"pzry9x0s0muk"      ;; No separator character
	    #*"1pzry9x0s0muk"     ;; Empty HRP
	    #*"x1b4n0q5v"         ;; Invalid data character
	    #*"li1dgmt3"          ;; Too short checksum
	    #*"de1lg7wt\xFF;" ;; Invalid character in checksum
	    #*"A1G7SGD8"          ;; checksum calculated with uppercase form of HRP
	    #*"10a06t8"           ;; empty HRP
	    #*"1qzzfhee"          ;; empty HRP
	    ))
(for-each (test-invalid-bech32 'bech32m)
	  '(
	    #*" 1xj0phk"          ;; HRP character out of range
	    #*"\x7F;1g6xzxy"  ;; HRP character out of range
	    #*"\x80;1vctc34"  ;; HRP character out of range
	    ;; overall max length exceeded
	    #*"an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4"
	    #*"qyrz8wqd2c9m"      ;; No separator character
	    #*"1qyrz8wqd2c9m"     ;; Empty HRP
	    #*"y1b0jsk6g"         ;; Invalid data character
	    #*"lt1igcx5c0"        ;; Invalid data character
	    #*"in1muywd"          ;; Too short checksum
	    #*"mm1crxm3i"         ;; Invalid character in checksum
	    #*"au1s5cgom"         ;; Invalid character in checksum
	    #*"M1VUXWEZ"          ;; Checksum calculated with uppercase form of HRP
	    #*"16plkw9"           ;; Empty HRP
	    #*"1p2gdwpf"          ;; Empty HRP
	    ))

(define ((test-valid-segwit-address hrp) test)
  (define (segwit-script-public-key witver witprog)
    (bytevector-append (u8-list->bytevector
			`(,(+ witver (if (zero? witver) 0 #x50))
			  ,(bytevector-length witprog)))
		       witprog))
  (let ((addr (car test))
	(hex (cadr test)))
    (let-values (((witver witprog) (segwit-decode hrp addr)))
      (let ((pubkey (segwit-script-public-key witver witprog)))
	(test-equal `(,hrp "Public key") (hex-string->bytevector hex) pubkey)
	(let ((r (segwit-encode hrp witver witprog)))
	  (test-equal `(,hrp "Re-encode") (string-downcase addr) r))))))

(for-each (test-valid-segwit-address "bc")
	  '(["BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4" "0014751e76e8199196d454941c45d1b3a323f1433bd6"]

	    ["bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y"
	     "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"]
	    ["BC1SW50QGDZ25J" "6002751e"]
	    ["bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs" "5210751e76e8199196d454941c45d1b3a323"]
	    
	    ["bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
	     "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"]))

(for-each (test-valid-segwit-address "tb")
	  '(#;["tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
	     "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"]
	    ["tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy"
	     "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"]
	    ["tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c"
	     "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"])) 

(define (test-invalid-address addr)
  (test-error (segwit-decode "bc" addr))
  (test-error (segwit-decode "tb" addr)))
(for-each test-invalid-address
	  '(
	    ;;  Invalid HRP
	    #*"tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut"
	    ;;  Invalid checksum algorithm (bech32 instead of bech32m)
	    #*"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd"
	    ;;  Invalid checksum algorithm (bech32 instead of bech32m)
	    #*"tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf"
	    ;;  Invalid checksum algorithm (bech32 instead of bech32m)
	    #*"BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL"
	    ;;  Invalid checksum algorithm (bech32m instead of bech32)
	    #*"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh"
	    ;;  Invalid checksum algorithm (bech32m instead of bech32)
	    #*"tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47"
	    ;;  Invalid character in checksum
	    #*"bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4"
	    ;;  Invalid witness version
	    #*"BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R"
	    ;;  Invalid program length (1 byte)
	    #*"bc1pw5dgrnzv"
	    ;;  Invalid program length (41 bytes)
	    #*"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav"
	    ;;  Invalid program length for witness version 0 (per BIP141)
	    #*"BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P"
	    ;;  Mixed case
	    #*"tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq"
	    ;;  More than 4 padding bits
	    #*"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf"
	    ;;  Non-zero padding in 8-to-5 conversion
	    #*"tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j"
	    ;;  Empty data section
	    #*"bc1gmk9yu"))

(define (test-invalid-addess-enc test)
  (let-values (((hrp version len) (apply values test)))
    (test-error (segwit-encode hrp version (make-bytevector len 0)))))
(for-each test-invalid-addess-enc
	  '(("BC" 0 20)
	    ("bc" 0 21)
	    ("bc" 17 32)
	    ("bc" 1 1)
	    ("bc" 16 41)))


(test-end)
