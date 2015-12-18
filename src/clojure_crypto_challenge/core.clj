(ns clojure-crypto-challenge.core
  (:require [clojure.java.io :as io]
            [clojure.math.numeric-tower :as math]
            [clojure.string :as string])
  (:import  java.util.Base64
            java.nio.charset.StandardCharsets
            javax.crypto.Cipher
            javax.crypto.spec.SecretKeySpec))


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

(def b64-decoder (Base64/getDecoder))

(defn decode-base64
  [ar]
  (vec (.decode b64-decoder (apply str ar))))


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

(defn encode-base64
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
  (format "%02x" y))

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

(defn- scale-to-frequency
  [x s]
  (->>
   x
   bigdec
   (* s)
   math/round
   int))

(def filename "./src/clojure_crypto_challenge/letters.csv")

(defn- clean-space [s] (if (= s "SPACE") " " s))

(defn- load-reference-lists
  [fname]
  (let [fl (slurp fname)
        digits (map bigdec (re-seq #"0\.[0-9]+" fl))
        letters (map #(apply short (clean-space %)) (re-seq #"[a-z]|SPACE" fl))
        ]
    (vector letters digits)))

(def llist (load-reference-lists filename))

                                        ;
;;; NASTYNESS TO REMOVE!!
;; (def full-array (int-array 128))
;; (dotimes [i (count (llist 0))]
;;   (aset-byte full-array
;;              (nth (llist 0) i)
;;              (byte  (int-multiply 30 (nth (llist 1) i)))))




(defn int-multiply
  [s v]
  (int (math/round (* s v))))

(defn- map-reference-lists
  [vs s]
  (zipmap (vs 0) (map #(int-multiply s %) (vs 1))))

(def memo-map-reference-lists
  (memoize map-reference-lists))

(def fixed-letter-map (memo-map-reference-lists llist 34))

(defn to-ascii-letter
  [y]
  (let [x (short y)]
    (if (and (> x 0x1F) (< x 0x80))
      (bit-or x 0x20)
      0x00)))


(defn chi-distance [^double x ^double y]
  (let [nay (or (nil? y) (= y 0))]
    (if nay (math/expt x 2) (/ (math/expt (-  x y) 2) y))))


(def line-sample 28) ;number of chars to determine english

(defn score-line-as-english
  [x]
  (let [c (take line-sample x)
        lm (memo-map-reference-lists llist (count c))]
    (->>
     c
     (map to-ascii-letter)
     frequencies
     (merge-with chi-distance lm)
     vals
     (reduce +)
     )))


(defn score-byte-on-code
  [c b]
  (let [s (repeat b)]
    (->>
     c
     (fixed-XOR s)
     score-line-as-english
     )))

(def all-bytes (range 255))

(defn get-XOR-score-table
  [s]
  (for [x all-bytes]
    [x (score-byte-on-code s x)]))

(defn min-tupple
  [i v]
  (apply min-key #(nth % i) v))

(defn get-XOR-score-best-match
  [s]
  (->>
   s
   get-XOR-score-table
   (min-tupple 1)))

(defn find-decode-byte
  [x]
  (first (get-XOR-score-best-match x)))


;;; Set 1 Challenge 4

(defn detect-single-character-XOR-in-file
  [f]
  (->>
   (line-seq (io/reader f))
   (map  decode-base16)
   (pmap get-XOR-score-best-match)
   (map cons (range))
   (min-tupple 2)
   ))

;;; Set 1 Challenge 5

(defn create-repeating-key
  [s]
  (flatten (repeat (map short s))))

(defn pattern-XOR-encode
  ([code-string code-key]
   (pattern-XOR-encode code-string code-key (fn [x] (identity x))))
  ([code-string code-key encode-fn]
   (let [e (create-repeating-key code-key)]
     (->>
      code-string
      (fixed-XOR e)
      encode-fn))))

;;; Set 1 Challenge 6
(defn- bit-count
  [x]
  (Integer/bitCount x))

(defn get-hamming-distance
  "Get hamming distance of two lists"
  [x y]
  (->>
   (fixed-XOR x y)
   (map bit-count)
   (reduce +)))

(defn get-keysize-edit-distance
  "get the mean keysize distance of k in the sequence
  of bytes ar. Do this n times. Returns a number"
  [ar k n]
  (let [s (partition k ar)
        t (rest s)
        g (take n s)
        h (take n t)]
    (apply min (map #(/ % k) (map get-hamming-distance g h)))))

(defn get-keysizes
  ([code-phrase] (get-keysizes code-phrase 4))
  ([code-phrase n] (get-keysizes code-phrase n 2 41))
  ([code-phrase n start end]
   (take n
         (map first
              (sort-by second
                       (for [i (range start end)]
                         [i (get-keysize-edit-distance code-phrase i 4)]))))))

(defn block-sequence
  [source block-width]
  (for [k (range block-width)]
    (take-nth block-width (drop k source))))

(defn bytes-to-string
  [x]
  (apply str (map char x)))


(defn break-repeat-XOR-cypher
  [code-phrase]
  (->>
   code-phrase
   get-keysizes
   (map #(block-sequence code-phrase %))
   (map #(map find-decode-byte %))
   (map #(fixed-XOR code-phrase (create-repeating-key %)))
   (map score-line-as-english)
   (zipmap (get-keysizes code-phrase))
   (apply min-key #(val %))
   first
   (block-sequence code-phrase)
   (map find-decode-byte)
   ))

;;; Set 1 Challenge 7 AES-128-ECB cyper

(defn decipher-aes-128-ecb
  "two strings, ky is key string, ct is cipher text. returns byte-array"
  [ky ct]
  (let [k (SecretKeySpec. (.getBytes ky) "AES")
        cipher (Cipher/getInstance "AES/ECB/NoPadding")]
    (.init cipher Cipher/DECRYPT_MODE k)
    (.doFinal cipher (byte-array ct))))
