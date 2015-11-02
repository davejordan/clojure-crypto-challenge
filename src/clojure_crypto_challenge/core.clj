(ns clojure-crypto-challenge.core
  (:gen-class))




(def base64-code
  (let
      [character-range '([\A \Z] [\a \z] [\0 \9])
       m (fn [[s e]] (vec (map char (range (byte s) (+ (byte e) 1)))))]
    (conj (reduce #(apply conj %1 %2)  (map m character-range)) \+ \/) ))


(defn convert-hexlet
  [b]
  (nth base64-code b))


(defn encode-3byte-array
  [b1 b2 b3]
  [(convert-hexlet (unsigned-bit-shift-right b1 2))
   (convert-hexlet (bit-or  (bit-shift-left b1 4) (bit-and b2 0b11110000)))
   (convert-hexlet (bit-or
                    (bit-shift-left (bit-and  b2 0b00001111) 2)
                    (unsigned-bit-shift-right b3 6)))
   (convert-hexlet (bit-and b3 0b00111111))])
