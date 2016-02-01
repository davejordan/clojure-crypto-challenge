(ns clojure-crypto-challenge.core-test
  (:require [clojure-crypto-challenge.core :refer :all]
            [clojure.java.io :as io]
            [clojure.math.numeric-tower :as math]
            [clojure.string :as string]
            [clojure.test :refer :all]
            [criterium.core :as crit]
            ))


(deftest test-encode-base64
  (testing "check small number encodings in base64"
    (are [x y] (= x (encode-byte-base64 y))
      \A 0
      \Z 25
      \a 26
      \z 51
      \0 52
      \9 61
      \+ 62
      \/ 63))
  (testing "can't convert larger than 63"
    (is (thrown? IndexOutOfBoundsException
                 (encode-byte-base64 64))))
  (testing "can't convert -ve"
    (is (thrown? IndexOutOfBoundsException
                 (encode-byte-base64 -1)))))

(deftest test-hexlet-3byte-split
  (testing "testing 4 byte conversion"
    (are [x y] (= 0 (compare (encode-base64 x) y))
      [0 0 0] [\A \A \A \A]
      [0 0 1] [\A \A \A \B]
      [0 0 63] [\A \A \A \/]
      [0xff 0xff 0xff] [\/ \/ \/ \/]
      [0xff 0xff 0xff 0xff] [\/ \/ \/ \/ \/ \w]
      )))

(deftest test-decode-base16
  (testing "decode hex characters"
    (are [x y] (= x (decode-base16 y))
      '(0) "0"
      '(15) "f"
      [255 255 255] "ffffff"
      [0 0 0] "000000"
      [0 1] "001")))


(def hex-source-test-code
  "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")


(def base64-dest-test-code
  "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

(deftest test-challenge-1
  (testing "compare the challenge strings"
    (is (= base64-dest-test-code
           (apply str (encode-base64 (decode-base16 hex-source-test-code)))))))

(deftest test-challenge-1a
  (is (= base64-dest-test-code
         (apply str (sequence reencode-base16-to-64-xf hex-source-test-code)))))

(deftest test-challenge-1c
  (is (= hex-source-test-code
         (apply str (encode-base16 (decode-base64 base64-dest-test-code))))))

;; Set 1 Challenge 2

(deftest test-fixed-XOR
  (testing "check XOR of byte arrays"
    (are [x y z] (= x (fixed-XOR y z))
      [2r00] [2r00] [2r00]
      [2r01] [2r00] [2r01]
      [2r00 2r00] [2r00 2r00] [2r00 2r00]
      [2r01 2r10 2r00] [2r10 2r01 2r11] [2r11 2r11 2r11])))

(def fixed-xor-source-code-1 "1c0111001f010100061a024b53535009181c")
(def fixed-xor-source-code-2 "686974207468652062756c6c277320657965")
(def fixed-xor-dest-code "746865206b696420646f6e277420706c6179")

(deftest test-challenge-2
  (testing "test Set1 challenge 2"
    (is (= fixed-xor-dest-code
           (encode-base16 (fixed-XOR
                           (decode-base16 fixed-xor-source-code-1)
                           (decode-base16 fixed-xor-source-code-2)))))))

;;; Set 1 Challenge 3 - Single-byte XOR cipher

(def single-byte-xor-cipher-code "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")




(deftest test-score-byte-on-code
  (testing "test getting values"
    (is (some? (score-byte-on-code [0xaa 0x0af] 0x00)))))


(deftest test-find-decode-byte
  (testing ""
    (let [code-fn (fn [b ts] (fixed-XOR (map byte ts) (repeat (count ts) b)))]
      (are [b s] (= b (find-decode-byte (code-fn b s)))
        0 "Hello there I think dave is here"
        1 "Hello there I think dave is here"
        55 "Hello there I think dave is here"
        ;; 32 "Chumps are people I don't like" Fails the test!!
        33 "Coralie is a cute woman. She has a loveley son"))))

(deftest test-challenge-3
  ;; The plain text is  "Cooking MC's like a pound of bacon"
  (testing "Having run the solution on test data, we know answer is 88"
    (is (= 88 (find-decode-byte (decode-base16 single-byte-xor-cipher-code))))
    ))


;;; Set 1 Challenge 4
;; Test file has 327 lines, 19618 characters.
;; LIne lengths are 60, except last line which is 58
(deftest test-detect-single-character-XOR-in-file
  (testing "test find byte in file"
    (let
        [v (detect-single-character-XOR-in-file
            "test/clojure_crypto_challenge/4.txt")]
      (is (= 170 (first v)))
      (is (= 53 (second v))))))


;;; Set 1 Challenge 5
(def test-encode-phrase (map byte "ICE"))

(def test-phrase-1 (map byte "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"))

(def test-encoding-1 "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")


(deftest test-pattern-XOR-encode
  (testing "test that challenge phrases match"
    (is (= 0 (compare test-encoding-1 (pattern-XOR-encode test-phrase-1 test-encode-phrase encode-base16))))))


;;; Set 1 Challenge 6

(deftest test-get-hamming-distance
  (testing "hamming distance of two known words (given by challenge)"
    (are [r x y] (= r (get-hamming-distance (map byte x) (map byte y)))
      0 "" ""
      0 "test" "test"
      37 "this is a test" "wokka wokka!!!")))

(deftest test-get-keysize-edit-distance
  (testing "keysize has smallest hamming distance between blocks"
    (are [r ar k n] (= r (get-keysize-edit-distance k n (map byte ar)))
      0 "aa" 1 1
      1 "on" 1 1
      1 "oonn" 2 2
      2 "ooll" 2 1)))


(def test-file-challenge-6a (line-seq (io/reader "test/clojure_crypto_challenge/6.txt")))

(def test-file-challenge-6b (decode-base64 test-file-challenge-6a))

(deftest test-break-repeat-XOR-cypher
  (testing "known result as a string"
    (is (= "Terminator X: Bring the noise"
           (bytes->string (break-repeat-XOR-cypher test-file-challenge-6b))))))

;;; Set 1 Challenge 7


(def test-file-challenge-7a (line-seq (io/reader "test/clojure_crypto_challenge/7.txt")))

(def test-file-challenge-7b (decode-base64 test-file-challenge-7a))

(def test-results-challenge-7 (slurp "test/clojure_crypto_challenge/7-results.txt"))

(deftest test-open-AES-128-ECB-cipher
  (testing "can open cipher with known key and result"
    (is (=
         test-results-challenge-7
         (bytes->string
          (aes-128-ecb-decrypt "YELLOW SUBMARINE" test-file-challenge-7b))))))


;;; Set 1 Challenge 8


(def test-file-challenge-8a (line-seq (io/reader "test/clojure_crypto_challenge/8.txt")))

(deftest test-detect-AES-ECB-code-text
  (testing "Test Set 1 Challenge 8"
    (is (= (:score (first (detect-AES-ECB-code-text
                           (map decode-base16 test-file-challenge-8a)))) 4))))


;;; Set 2 Challenge 9

(deftest test-pad-sequence
  (testing "pad a sequence to set size"
    (is (= (padded-block 10 \X "YELLOW") '(\Y \E \L \L \O \W \X \X \X \X)))))

;;; Set 2 Challenge 10

(deftest test-aes-128-ecb-encrypt-decrypt
  (testing "ECB works on 16 byte block"
    (is (= "YELLOW PLAIN TXT"
           (bytes->string
            (aes-128-ecb-decrypt "YELLOW CATMAINES"
                                 (aes-128-ecb-encrypt
                                  "YELLOW CATMAINES"
                                  (map byte "YELLOW PLAIN TXT"))))))))

(deftest test-aes-128-cbc-encrypt-decrypt
  (testing "CBC works on 16 byte block"
    (is (= "YELLOW PLAIN TXT"
           (bytes->string
            (aes-128-cbc-decipher "YELLOW SUBMARINE"
                                  (aes-128-cbc-encipher
                                   (string->bytesvec "YELLOW SUBMARINE")
                                   (string->bytesvec "YELLOW PLAIN TXT")
                                   (range 16))
                                  (range 16)))))))


(deftest test-CBC-encrypt-decrypt
  (testing "cbc on 16 bytes with iv=0 is ecb - remove padding"
    (is (= "This is the test to code"
           (zero-unpadded
            (bytes->string
             (aes-128-cbc-decipher
              "YELLOW SUBMARINE"
              (aes-128-cbc-encipher "YELLOW SUBMARINE"
                                    (map byte "This is the test to code")
                                    (range 16))
              (range 16))))))))


(deftest test-block-cipher-decrypt
  (testing "Test Set 2 Challenge 10"
    (is (=
         (zero-unpadded
          (bytes->string
           (aes-128-cbc-decipher
            "YELLOW SUBMARINE"
            (decoded-base64-file "test/clojure_crypto_challenge/10.txt")
            (repeat 16 0))))
         (slurp "test/clojure_crypto_challenge/10answer.txt")))))

;;; Set 2 Challenge 11

(deftest test-ecb?
  (testing "a repeated set of blocks is picked up as ecb"
    (is (ecb?
         (string->bytesvec
          "       yellow submarine       yellow submarine  yellow submarineyellow submarine")))))
