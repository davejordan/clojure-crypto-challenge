(ns clojure-crypto-challenge.core
  (:require [clojure.string :as string]
            [clojure.math.numeric-tower :as math]))


;; Set 1 Challenge 1 - Re-encode base16 to base64
(defn encode-byte-base64
  [b]
  (nth [\A \B \C \D \E \F \G \H \I \J \K \L \M \N \O \P \Q \R \S \T \U \V \W
        \X \Y \Z \a \b \c \d \e \f \g \h \i \j \k \l \m \n \o \p \q \r \s \t
        \u \v \w \x \y \z \0 \1 \2 \3 \4 \5 \6 \7 \8 \9 \+ \/] b))

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

(defn decode-character-base16
  [x]
  (Integer/parseInt (str x) 16))

(def decode-base16-xf
  "Tranducer. Decodes hex string to byte array"
  (comp
   (partition-all 2)
   (map #(apply str %))
   (map decode-character-base16)))

(def encode-base64-xf
  "Tranducer. Encodes byte array to base64 char array"
  (comp
   (partition-all 3)
   (mapcat hexlet-padded-3byte-split)
   (map encode-byte-base64)))

(defn base64-encode
  [xa]
  (vec (sequence encode-base64-xf xa)))

(def reencode-base16-to-64-xf
  "Transducer. Reencodes a string of Hex to base64 char array"
  (comp
   decode-base16-xf
   encode-base64-xf))


(defn decode-base16
  [xs]
  (sequence decode-base16-xf xs))

(defn format-byte-as-hex
  [y]
  (format "%h" y))

(defn encode-base16
  "Encode an array of bytes to a string of Hex"
  [xs]
  (->>
   xs
   (map format-byte-as-hex)
   (apply str)))

;; Set 1 Challenge 2 - Fixed XOR
(defn fixed-XOR
  "xor each byte in arrays x and y. x and y must be same length"
  [x y]
  (map bit-xor x y))


;;; Set 1 Challenge 3 - Single-byte XOR cipher

;;;  Letter  Frequency

(def letter-frequencies
  {\E 0.1202, \T 0.910, \A 0.812, \O 0.768, \I 0.731, \N 0.695,
   \S 0.628, \R 0.602, \H 0.592, \D 0.432, \L 0.398, \U 0.288, \C 0.271,
   \M 0.261, \F 0.230, \Y 0.211, \W 0.209, \G 0.203, \P 0.182, \B 0.149,
   \V 0.111, \K 0.069, \X 0.017, \Q 0.011, \J 0.010, \Z 0.007 })

(defn is-whitespace?
  [c]
  (Character/isWhitespace c))

(defn to-upper-case
  [c]
  (Character/toUpperCase c))

(def sanitise-char-array-xf
  (comp
   (remove is-whitespace?)
   (map to-upper-case)
   (map char)))

(defn frequencies-upper-case-insensitive
  [l]
  (frequencies (sequence sanitise-char-array-xf l)))

(defn relative-distributions
  [value-map]
  (let
      [total (reduce + (vals value-map))
       fn (fn [k v] [k (/ v total)])]
    (into {} (map fn (keys value-map) (vals value-map)))))

(defn compare-scores
  [x y]
  (/ (inc x) (inc y)))

(defn seq-average
  [s]
  (let [t (reduce + s)
        c (count s)]
    (if (not= 0 c) (/ t c)
        0)))

(defn single-Byte-fixed-XOR
  [char-arr b]
  (let [byte-arr (repeat (count char-arr) b)]
    (fixed-XOR byte-arr char-arr)))


(defn score-byte-on-code
  [c b]
  (let [s (repeat (count c) b)]
    (->>
     c
     (fixed-XOR s)
     (frequencies-upper-case-insensitive)
     (relative-distributions)
     (merge-with compare-scores letter-frequencies)
     (vals)
     (seq-average)
     )))

(defn find-decode-byte
  [s]
  (second (first (sort-by #(/ 1 (first %)) (for [x (range 0xff)]
                                             [(score-byte-on-code s x) x])))))
