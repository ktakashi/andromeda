;;; -*- mode: scheme; coding: utf-8 -*-
;;; Copyright 2024 Takashi Kato
;;; 
;;; Licensed under the Apache License, Version 2.0 (the "License");
;;; you may not use this file except in compliance with the License.
;;; You may obtain a copy of the License at
;;; 
;;;     http://www.apache.org/licenses/LICENSE-2.0
;;; 
;;; Unless required by applicable law or agreed to in writing, software
;;; distributed under the License is distributed on an "AS IS" BASIS,
;;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;;; See the License for the specific language governing permissions and
;;; limitations under the License.

;; Ref
;; - Bech32: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
;; - Bech32m: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

#!nounbound
#!read-macro=sagittarius/bv-string
(library (andromeda bip bech32)
    (export segwit-encode segwit-decode

	    bech32-encode bech32-decode

	    bech32-encoding
	    *bech32-encoding*
	    *bech32m-encoding*
	    )
    (import (rnrs)
	    (rfc base32)
	    (rfc base-n)
	    (srfi :1 lists)
	    (util bytevector))

(define *charset* #*"qpzry9x8gf2tvdw0s3jn54khce6mua7l=")
(define *bech32-encode-table* (list->vector (bytevector->u8-list *charset*)))
(define *bech32-decode-table*
  (base-n-encode-table->decode-table *bech32-encode-table*))

(define-enumeration bech32-encoding
  (bech32 bech32m)
  bech32-encodings)
(define *bech32-encodings* (enum-set-universe (bech32-encodings)))
(define (bech32-encoding? o) (enum-set-member? o *bech32-encodings*))
(define *bech32-encoding* (bech32-encoding bech32))
(define *bech32m-encoding* (bech32-encoding bech32m))
(define *bech32m-const* #x2bc830a3)

;; sad table
(define *dumb-table* (list->vector (iota 128)))

(define (segwit-decode (hrp string?) (addr string?))
  (define lower (string-downcase addr))
  (unless (or (string=? lower addr) (string=? (string-upcase addr) addr))
    (assertion-violation 'segwit-decode
			 "Address must be all lower or all upper" addr))
  (let-values (((hrpgot data spec) (bech32-decode (string->utf8 lower))))
    (unless (string=? (utf8->string hrpgot) hrp)
      (error 'segwit-decode "Unexpected hrp" hrpgot))
    (let ((decoded (base32-decode (bytevector-copy data 1)
				  :decode-table *dumb-table*)))
      (define len (bytevector-length decoded))
      (define v (bytevector-u8-ref data 0))

      (unless (<= 2 len 40) (error 'segwit-decode "Address is too long"))
      (when (> v 16) (error 'segwit-decode "Unknown version"))
      (when (and (zero? v) (not (= len 20)) (not (= len 32)))
	(error 'segwit-decode "Invalid address length"))
      (when (or (and (zero? v) (not (eq? spec *bech32-encoding*)))
		(and (not (zero? v)) (not (eq? spec *bech32m-encoding*))))
	(error 'segwit-decode "Invalid Bech32 encoding"))
      (values v decoded))))

(define (segwit-encode (hrp string?) (witver integer?) (witprog bytevector?))
  (define bvhrp (string->utf8 (string-downcase hrp)))
  (let* ((spec (if (zero? witver) *bech32-encoding* *bech32m-encoding*))
	 ;; only convert 8bit -> 5 bits
	 (encoded (base32-encode witprog :encode-table *dumb-table*
				 :padding? #f))
	 (encoding (bytevector-append (make-bytevector 1 witver) encoded))
	 (ret (utf8->string (bech32-encode bvhrp encoding spec))))
    (segwit-decode hrp ret)
    ret))
    

(define (bech32-encode (hrp bytevector?) (data bytevector?) (encoding bech32-encoding?))
  (define (encode out data)
    (define len (bytevector-length data))
    (do ((i 0 (+ i 1)))
	((= i len))
      (let ((v (bytevector-u8-ref data i))) 
	(put-u8 out (vector-ref *bech32-encode-table* v)))))
  (let ((checksum (bech32-compute-checksum hrp data encoding)))
    (let-values (((out e) (open-bytevector-output-port)))
      (put-bytevector out hrp)
      (put-bytevector out #*"1")
      (encode out data)
      (encode out checksum)
      (e))))

(define (bech32-decode (bech bytevector?))
  (define (err) (assertion-violation 'bech32-decode "Invalid Bech32"))
  (define (decode data)
    (define len (bytevector-length data))
    (let ((out (make-bytevector len)))
      (do ((i 0 (+ i 1)))
	  ((= i len) out)
	(let ((v (bytevector-u8-ref data i)))
	  (bytevector-u8-set! out i (vector-ref *bech32-decode-table* v))))))
  (define len (bytevector-length bech))
  (unless (for-all (lambda (x) (< 33 x 126)) (bytevector->u8-list bech)) (err))
  ;; TODO should be convert case?
  (cond ((bytevector-index-right bech (char->integer #\1)) =>
	 (lambda (index)
	   (when (or (< index 1) (< len (+ index 7)) (< 90 len)) (err))
	   (let*-values (((hrp tmp) (bytevector-split-at* bech index))
			 ((encoded) (bytevector-copy tmp 1)))
	     (let* ((data (decode encoded))
		    (spec (bech32-verify-checksum hrp data)))
	       (unless spec (err))
	       (values hrp
		       (bytevector-copy data 0 (- (bytevector-length data) 6))
		       spec)))))
	(else (err))))

(define (bech32-verify-checksum hrp data)
  (let ((v (bech32-polymod (bytevector-append (bech32-hrp-expand hrp) data))))
    (cond ((= v 1)               *bech32-encoding*)
	  ((= v *bech32m-const*) *bech32m-encoding*)
	  (else #f))))

(define (bech32-compute-checksum hrp data encoding)
  (let* ((values (bytevector-append (bech32-hrp-expand hrp)
				    data #vu8(0 0 0 0 0 0)))
	 (mod (bitwise-xor (bech32-polymod values)
			   (case encoding
			     ((bech32) 1)
			     ((bech32m) *bech32m-const*))))
	 (r (make-bytevector 6)))
    (do ((i 0 (+ i 1)) (len (bytevector-length r)))
	((= i len) r)
      (let* ((n (* 5 (- 5 i)))
	     (v (bitwise-and (bitwise-arithmetic-shift-right mod n) #x1F)))
	(bytevector-u8-set! r i v)))))

(define *generator* #(#x3b6a57b2 #x26508e6d #x1ea119fa #x3d4233dd #x2a1462b3))
(define (bech32-polymod values)
  (define lsh bitwise-arithmetic-shift-left)
  (define rsh bitwise-arithmetic-shift-right)
  (define len (bytevector-length values))
  (define (next-chk chk top i)
    (if (odd? (rsh top i))
	(bitwise-xor chk (vector-ref *generator* i))
	chk))
  (let loop ((i 0) (chk 1))
    (if (= i len)
	chk
	(let* ((top (rsh chk 25))
	       (v (bytevector-u8-ref values i))
	       (chk (bitwise-xor (lsh (bitwise-and chk #x1ffffff) 5) v)))
	  (do ((j 0 (+ j 1)) (chk chk (next-chk chk top j)))
	      ((= j 5) (loop (+ i 1) chk)))))))

(define (bech32-hrp-expand hrp)
  (define lsh bitwise-arithmetic-shift-left)
  (define rsh bitwise-arithmetic-shift-right)
  (define len (bytevector-length hrp))
  (let-values (((out e) (open-bytevector-output-port)))
    (do ((i 0 (+ i 1)))
	((= len i))
      (let ((v (bytevector-u8-ref hrp i)))
	(put-u8 out (rsh v 5))))
    (put-u8 out 0)
    (do ((i 0 (+ i 1)))
	((= len i))
      (let ((v (bytevector-u8-ref hrp i)))
	(put-u8 out (bitwise-and v #x1F))))
    (e)))


)
