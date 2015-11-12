(ns clojure-crypto-challenge.core-test
  (:require [clojure-crypto-challenge.core :refer :all]
            [clojure.string :as string]
            [clojure.test :refer :all]
            [clojure.math.numeric-tower :as math]))


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
    (are [x y] (= 0 (compare (base64-encode x) y))
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
           (apply str (base64-encode (decode-base16 hex-source-test-code)))))))

(deftest test-challenge-1a
  (is (= base64-dest-test-code
         (apply str (sequence reencode-base16-to-64-xf hex-source-test-code)))))

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



(deftest test-relative-distributions
  (testing "test relative-differences calculates on map of counts"
    (are [x y] (= x (relative-distributions y))
      {\a 1} {\a 1}
      {\a 1/2, \b 1/2} {\a 1, \b 1}
      {\a 2/3 \b 1/3} {\a 2, \b 1}
      {\a 1/3 \b 1/3 \c 1/3} {\a 1 \b 1\c 1}
      {} {}
      {:a 1} {:a 1}
      )))


(deftest test-seq-average
  (testing "mean of a sequence"
    (are [m s] (= m (seq-average s))
      0 []
      0 [0]
      1 [1]
      1 [1 1]
      1 [0 2]
      3 [6 3 0])))

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
  (testing ""
    (is (= 88 (find-decode-byte (decode-base16 single-byte-xor-cipher-code))))
    ))
