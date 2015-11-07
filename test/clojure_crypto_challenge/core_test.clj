(ns clojure-crypto-challenge.core-test
  (:require [clojure-crypto-challenge.core :refer :all]
            [clojure.string :as string]
            [clojure.test :refer :all]))


(deftest test-hex-to-64
  (testing "convert single byte"
    (are [x y] (= x (convert-hexlet y))
      \A 0
      \Z 25
      \a 26
      \z 51
      \0 52
      \9 61
      \+ 62
      \/ 63)))

(deftest test-convert-4byte-array
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

(deftest test-count-occurences
  (testing "test count-occurence"
    (are [x y] (= x (count-occurences {} y))
      {\a 1} "a"
      {\a 5} "aaaaa"
      {} ""
      {\a 3 \b 3} "ababab")))

(deftest test-relative-differences
  (testing "test relative-differences calculates on map of counts"
    (are [x y] (= x (relative-differences y))
      {\a 1} {\a 1}
      {\a 1/2, \b 1/2} {\a 1, \b 1}
      {\a 2/3 \b 1/3} {\a 2, \b 1}
      {\a 1/3 \b 1/3 \c 1/3} {\a 1 \b 1\c 1}
      {} {}
      {:a 1} {:a 1}
      )))

(deftest test-is-word-score
  (testing "test the scoring of a string as a phrase"
    (are [x m y] (== x (is-word-score m y))
      1 {:A 0.5 :B 0.5} {:A 0.5 :B 0.5}
      1/3 {:A 1 :B 2} {:A 2 :B 1}
      1 {:A 1} {:A 1}
      2/3 {:A 1 :B 2} {:A 2}
      )))

(deftest test-is-word-throws-exception
  (testing "is-word-score throws exception if key not in map"
    (is (thrown? NullPointerException (is-word-score {:A 1} {:A 1 :B 1})))))






(def d-list (rat single-byte-xor-cipher-code letter-frequencies #(map char %)))

(def th (reduce merge {} d-list))

th

(filter #(= (val %) (apply max (vals th))) th)


(apply str (map char (fixed-XOR (decode-base16 single-byte-xor-cipher-code)
                                (repeat (count single-byte-xor-cipher-code) 249))))
