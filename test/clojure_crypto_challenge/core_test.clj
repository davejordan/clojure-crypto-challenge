(ns clojure-crypto-challenge.core-test
  (:require [clojure.test :refer :all]
            [clojure-crypto-challenge.core :refer :all]))


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
    (is (= 0 (compare (encode-3byte-array [0 0 0]) [\A \A \A \A])))))
