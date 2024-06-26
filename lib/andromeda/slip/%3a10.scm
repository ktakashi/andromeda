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
    (export generate-master-key
	    derive-private-key derive-public-key

	    *curve:secp256k1*
	    *curve:nist256p1*
	    *curve:ed25519*

	    slip10-key? slip10-key-derivation-path

	    master-key?
	    derivable-key? derivable-key-k derivable-key-c
	    derivable-key->private-key
	    derived-public-key?
	    derived-public-key-raw-value
	    derived-public-key->public-key
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

(define-record-type slip10-key
  ;; derivation-path holds list of path in reverse order
  ;; e.g. (80000001 0) represents m/0/1'
  ;; '() means master key
  ;; This is needed for SLIP-0032
  (fields derivation-path))

(define-record-type derivable-key
  (parent slip10-key)
  (fields curve k c >private-key)
  (protocol
   (lambda (p)
     (define (->private-key curve k)
       (if curve
	   (generate-private-key *key:ecdsa* (bytevector->uinteger k) curve)
	   (generate-private-key *key:ed25519* k)))
     (lambda (path curve k c)
       (let ((private-key (->private-key curve k)))
	 ((p path) curve k c private-key))))))
(define (master-key? o)
  (and (derivable-key? o) (null? (slip10-key-derivation-path o))))

(define-record-type derived-public-key
  (parent slip10-key)
  (fields curve
	  raw-value
	  ;; lazy way to make it look like conversion procedure :)
	  >public-key))

(define-enumeration slip-curve
  (secp256k1 nist256p1 ed25519)
  slip-curves)
(define *slip-curves* (enum-set-universe (slip-curves)))
(define (slip-curve? v) (enum-set-member? v *slip-curves*))

(define *curve:secp256k1* (slip-curve secp256k1))
(define *curve:nist256p1* (slip-curve nist256p1))
(define *curve:ed25519*   (slip-curve ed25519))

(define (generate-master-key (curve slip-curve?) (S bytevector?))
  (define (check param a)
    (and (< a (ec-parameter-n param)) (not (zero? a))))
  (unless (<= 128 (* (bytevector-length S) 8) 512)
    (assertion-violation 'generate-master-key
			 "S must be 128bit to 512bit in length"))
  (let-values (((param modifier) (slip-curve->curve&seed curve)))
    (let loop ((seed S))
      (let* ((mac (make-mac *mac:hmac* modifier :digest *digest:sha-512*))
	     (I (generate-mac mac seed)))
	(let-values (((IL IR) (bytevector-split-at* I 32)))
	  (if (or (not param) (check param (bytevector->uinteger IL)))
	      (make-derivable-key '() param IL IR)
	      (loop I)))))))

(define (hardened-child-key i) (+ i (expt 2 31)))
(define (hardened-key? i) (>= i (expt 2 31)))
(define (derive-private-key (key derivable-key?) i)
  (define k (derivable-key-k key))
  (define c (derivable-key-c key))
  (define param (derivable-key-curve key))
  (define uk (bytevector->uinteger k))
  (define path (cons i (slip10-key-derivation-path key)))
  (define (check param IL k)
    (let* ((a (bytevector->uinteger IL))
	   (key (mod (+ a uk) (ec-parameter-n param))))
      (and (< a (ec-parameter-n param))
	   (not (zero? key))
	   (uinteger->bytevector key 32))))
  (define (raw-public-key key)
    (derived-public-key-raw-value (derive-public-key key)))
  (define (compute-d i param)
    (cond ((hardened-key? i) (bytevector-append #vu8(#x00) k buf))
	  ((not param)
	   (assertion-violation 'derive-private-key
	    "ed25519 doesn't support normal child key derivation"))
	  (else (bytevector-append (raw-public-key key) buf))))
  (define buf (make-bytevector 4))
  (unless (= (bytevector-length k) 32)
    (assertion-violation 'derive-private-key "Invalid length of k"))
  (unless (= (bytevector-length c) 32)
    (assertion-violation 'derive-private-key "Invalid length of c"))
  (bytevector-u32-set! buf 0 i (endianness big))
  (let loop ((d (compute-d i param)))
    (let* ((mac (make-mac *mac:hmac* c :digest *digest:sha-512*))
	   (I (generate-mac mac d)))
      (let-values (((IL IR) (bytevector-split-at* I 32)))
	(cond ((not param) (make-derivable-key path param IL IR))
	      ((check param IL k) =>
	       (lambda (key) (make-derivable-key path param key IR)))
	      (else (loop (bytevector-append #vu8(#x01) IR buf))))))))

(define (derive-public-key (key derivable-key?))
  (define k (derivable-key-k key))
  (define param (derivable-key-curve key))
  (define path (slip10-key-derivation-path key))
  (if param
      (let* ((Q (ec-point-mul (ec-parameter-curve param)
			      (ec-parameter-g param)
			      (bytevector->uinteger k)))
	     (pk (uinteger->bytevector (ec-point-x Q) 32))
	     ;; compression mode, #x02 or #x03
	     ;; maybe we should make a procedure to convert points to
	     ;; compressed format
	     (parity (make-bytevector 1)))
	(bytevector-u8-set! parity 0 (if (even? (ec-point-y Q)) 2 3))
	(make-derived-public-key path param
	 (bytevector-append parity pk)
	 (generate-public-key *key:ecdsa* (ec-point-x Q) (ec-point-y Q) param)))
      (let ((public-key (eddsa-private-key-public-key 
			 (generate-private-key *key:ed25519* k))))
	(make-derived-public-key path #f
	 (bytevector-append #vu8(#x00) (eddsa-public-key-data public-key))
	 public-key))))

(define (slip-curve->curve&seed curve)
  (case curve
    ((secp256k1) (values *ec-parameter:secp256k1* *bitcoin-seed*))
    ((nist256p1) (values *ec-parameter:p256*      *nist-256p1-seed*))
    ;; No ec-parameter for Ed25519
    ((ed25519)   (values #f                       *ed25519-seed*))))
)
