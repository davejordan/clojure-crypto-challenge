(ns clojure-crypto-challenge.core
  (:require [clojure.string :as string]
            [clojure.math.numeric-tower :as math]))

(defn encode-byte-base64
  [b]
  (let [crs [[\A \Z] [\a \z] [\0 \9]]
        rfn (fn [[a b]] (range (byte a) (inc (byte b))))
        rconj (fn [x y m] (conj (vec  m) x y))]
    (nth (->>
          crs
          (map rfn)
          (rconj \+ \/)
          flatten
          (map char)) b)))


(defn hexlet-3byte-split
  "Returns a hexlet representation of a 3 Byte array"
  [[b1 b2 b3]]
  [(unsigned-bit-shift-right b1 2) ;h1
   (bit-or (bit-shift-left (bit-and b1 2r00000011) 4)
           (unsigned-bit-shift-right b2 4)) ;h2
   (bit-or (bit-shift-left (bit-and b2 2r00001111) 2)
           (unsigned-bit-shift-right b3 6)) ;h3
   (bit-and b3 2r00111111)])

(defn hexlet-padded-3byte-split
  "Returns a hexlet representation of a byte array.
  Expects an array of bytes. Length <= 3."
  [t]
  (let [s (count t)
        padding (- 3 s)
        tk (+ 1 s)
        pad (into (vec t) (repeat padding 0))]
    (take tk (hexlet-3byte-split pad))))

;; (defn base64-encode
;;   "Encode a sequence of bytes in base64 (radix)"
;;   [xa]
;;   (->>
;;    (partition-all 3 xa)
;;    ( mapcat hexlet-padded-3byte-split)
;;    ( map encode-byte-base64)
;;    vec))


(defn decode-character-base16
  [x]
  (Integer/parseInt (str x) 16))

(def decode-base16-xf
  (comp
   (partition-all 2)
   (map #(apply str %))
   (map decode-character-base16)))

(def encode-base64-xf
  (comp
   (partition-all 3)
   (mapcat hexlet-padded-3byte-split)
   (map encode-byte-base64)))

(defn base64-encode
  [xa]
  (vec (sequence encode-base64-xf xa)))

(def reencode-base16-to-64-xf
  (comp
   decode-base16-xf
   encode-base64-xf))


;; (defn decode-base16
;;   "Decode a base16 string to numbers"
;;   [xs]
;;   (->>
;;    xs
;;    (partition-all 2)
;;    (map (fn [y] (apply str y)))
;;    (map decode-character-base16)))

(defn decode-base16
  [xs]
  (sequence decode-base16-xf xs))



(defn encode-base16
  "Encode an array of bytes to a string of Hex"
  [xs]
  (->>
   xs
   (map (fn [y] (format "%h" y)))
   (apply str)))

;; Set 1 Challenge 2 - Fixed XOR
(defn fixed-XOR
  "xor each byte in arrays x and y. x and y must be same length"
  [x y]
  (map bit-xor x y))


;;; Set 1 Challenge 2 - Single-byte XOR cipher

;;;  Letter  Frequency
(def letter-frequencies-100
  {:E 12.02, :T 9.10, :A 8.12, :O 7.68, :I 7.31, :N 6.95,
   :S 6.28, :R 6.02, :H 5.92, :D 4.32, :L 3.98, :U 2.88, :C 2.71,
   :M 2.61, :F 2.30, :Y 2.11, :W 2.09, :G 2.03, :P 1.82, :B 1.49,
   :V 1.11, :K 0.69, :X 0.17, :Q 0.11, :J 0.10, :Z 0.07 })

(def letter-frequencies
  {:E 0.1202, :T 0.910, :A 0.812, :O 0.768, :I 0.731, :N 0.695,
   :S 0.628, :R 0.602, :H 0.592, :D 0.432, :L 0.398, :U 0.288, :C 0.271,
   :M 0.261, :F 0.230, :Y 0.211, :W 0.209, :G 0.203, :P 0.182, :B 0.149,
   :V 0.111, :K 0.069, :X 0.017, :Q 0.011, :J 0.010, :Z 0.007 })

;; letter count

(def test-string "aababa22f452fffaaa000001234f")

(defn count-occurences
  [m l]
  (let [h (first l)
        f (fn[a] (= h a))]
    (cond
      (some? h) (count-occurences
                 (assoc m h (count (filter f l)))
                 (remove f l))
      :else m)))

(defn count-occurences-case-insensitive
  [l]
  (->>
   l
   (map string/upper-case)
   (count-occurences {})))

(defn relative-differences
  [m]
  (let [c (reduce + (vals m))
        s (seq m)]
    (reduce #(assoc
              %1
              (first %2)
              (/ (second %2) c)) {} s)))



(defn is-word-score
  "difference the scores for each key in w against reference in m.
  if key not in m, exception. divides difference by total of reference (m),
  and subtracts from 1. Assumes total for maps is 1. "
  [m w]
  (let [total (reduce + (vals m))]
    (- 1 (/
          (reduce
           +
           (map #(math/abs (- (second %) (get m (first %)))) w))
          total))))


(defn convert-char-to-key
  [c]
  (keyword (string/upper-case (str c))))


;; HACK
(defn cat
  "Convert the values of s to keys, and count occurences"
  [s]
  (count-occurences {} (map convert-char-to-key s)))


(defn dog
  "c is occurence map, lf is letter frequency reference.
  Returns a map of only occurrences that are in lf"
  [c lf]
  (let [ks (keys lf)
        mks (keys (apply dissoc c ks))]
    (apply dissoc c mks)))

(defn convert-byte-to-char
  [x] (map char x))



(defn apply-single-Byte-XOR
  "Crack code-string by XOR
  crack using crack-byte. Returns an array of numbers (bytes)"
  [code-string crack-byte]
  (let [
        decoded-length (count code-string)
        test-array (repeat decoded-length crack-byte)
        ]
    (fixed-XOR code-string test-array)))

(defn single-byte-XOR-crack-hexstring
  [code crack-byte]
  [])



(defn rat
  "Create a list of words-scores aginst full range of possible byte values
  "
  [code-string letter-distribution encoding-fn]
  (let [
        test-byte-range (range 0xff)]
    (for [x test-byte-range
          :let [
                b16-code-string (decode-base16 code-string)
                crack-attempt (apply-single-Byte-XOR b16-code-string x)
                crack-char-array (map char crack-attempt)
                code-occurence-map (cat crack-attempt)
                filtered-code-occurence-map (dog code-occurence-map letter-distribution)
                occurence-map-compare (= (count code-occurence-map)
                                         (count filtered-code-occurence-map))]]
      ;; (when occurence-map-compare
      { x
       [(apply str crack-attempt)
        filtered-code-occurence-map
        (is-word-score letter-distribution filtered-code-occurence-map)]}
      ;; )
      )))
