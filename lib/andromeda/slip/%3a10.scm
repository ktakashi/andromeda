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
;; - https://github.com/satoshilabs/slips/blob/master/slip-0010.md

#!nounbound
#!read-macro=sagittarius/bv-string
(library (andromeda slip :10)
    (export generate-master-key slip-curve
	    derive-private-key derive-public-key

	    deriveable-key? deriveable-key-k deriveable-key-c
	    hardened-child-key)
    (import (rnrs)
	    (sagittarius)
	    (sagittarius crypto digests)
	    (sagittarius crypto mac)
	    (sagittarius crypto math ec)
	    (sagittarius crypto keys)
	    (util bytevector))

(define *bitcoin-seed*    #*"Bitcoin seed")
(define *nist-256p1-seed* #*"Nist256p1 seed")
(define *ed25519-seed*    #*"ed25519 seed")

(define-record-type deriveable-key (fields k c))

(define-enumeration slip-curve
  (secp256k1 nist256p1 ed25519)
  slip-curves)
(define *slip-curves* (enum-set-universe (slip-curves)))
(define (slip-curve? v) (enum-set-member? v *slip-curves*))

(define (generate-master-key (curve slip-curve?) (S bytevector?))
  (define (check param a)
    (and (< a (ec-parameter-n param)) (not (zero? a))))
  (unless (<= 128 (* (bytevector-length S) 8) 512)
    (assertion-violation 'generate-master-key
			 "S must be 128bit to 512bit in length"))
  (let-values (((param master-seed) (slip-curve->curve&seed curve)))
    (let loop ((seed master-seed))
      (let* ((mac (make-mac *mac:hmac* seed :digest *digest:sha-512*))
	     (I (generate-mac mac S)))
	(let-values (((IL IR) (bytevector-split-at* I 32)))
	  (if (or (not param) (check param (bytevector->uinteger IL)))
	      (make-deriveable-key IL IR)
	      (loop I)))))))

(define (hardened-child-key i) (+ i (expt 2 31)))
(define (hardened-key? i) (>= i (expt 2 31)))
(define (derive-private-key (curve slip-curve?)
			    (key deriveable-key?)
			    i)
  (define k (deriveable-key-k key))
  (define c (deriveable-key-c key))
  (define uk (bytevector->uinteger k))
  (define (check param IL k)
    (let* ((a (bytevector->uinteger IL))
	   (key (mod (+ a uk) (ec-parameter-n param))))
      (and (< a (ec-parameter-n param))
	   (not (zero? key))
	   (uinteger->bytevector key 32))))
  (define buf (make-bytevector 4))
  (unless (= (bytevector-length k) 32)
    (assertion-violation 'derive-private-key "Invalid length of k"))
  (unless (= (bytevector-length c) 32)
    (assertion-violation 'derive-private-key "Invalid length of c"))
  (bytevector-u32-set! buf 0 i (endianness big))
  (let-values (((param _) (slip-curve->curve&seed curve)))
    (let loop ((d (if (hardened-key? i)
		      (bytevector-append #vu8(#x00) k buf)
		      (bytevector-append (derive-public-key curve key) buf))))
      (let* ((mac (make-mac *mac:hmac* c :digest *digest:sha-512*))
	     (I (generate-mac mac d)))
	(let-values (((IL IR) (bytevector-split-at* I 32)))
	  (cond ((not param) (make-deriveable-key IL IR))
		((check param IL k) =>
		 (lambda (key) (make-deriveable-key key IR)))
		(else (loop (bytevector-append #vu8(#x01) IR buf)))))))))

(define (derive-public-key (curve slip-curve?) (key deriveable-key?))
  (define k (deriveable-key-k key))
  (case curve
    ((ed25519)
     (bytevector-append #vu8(#x00)
      (eddsa-public-key-data
       (eddsa-private-key-public-key (generate-private-key *key:ed25519* k)))))
    (else
     (let-values (((param _) (slip-curve->curve&seed curve)))
       (let* ((Q (ec-point-mul (ec-parameter-curve param)
			       (ec-parameter-g param)
			       (bytevector->uinteger k)))
	      (pk (uinteger->bytevector (ec-point-x Q) 32))
	      (parity (make-bytevector 1)))
	 (bytevector-u8-set! parity 0 (+ 2 (bitwise-and (ec-point-y Q) 1)))
	 (bytevector-append parity pk))))))

(define (slip-curve->curve&seed curve)
  (case curve
    ((secp256k1) (values *ec-parameter:secp256k1* *bitcoin-seed*))
    ((nist256p1) (values *ec-parameter:p256*      *nist-256p1-seed*))
    ;; No ec-parameter for Ed25519
    ((ed25519)   (values #f                       *ed25519-seed*))))
)