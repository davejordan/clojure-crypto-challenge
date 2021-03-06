(ns clojure-crypto-challenge.core
  (:require [clojure.java.io :as io]
            [clojure.math.numeric-tower :as math]
            [clojure.string :as string]
            [criterium.core :as crit])
  (:import java.nio.charset.StandardCharsets
           java.util.Base64
           javax.crypto.Cipher
           javax.crypto.spec.SecretKeySpec))

(defn string->bytesvec
  "robust way to convert string to vector of bytes"
  [s]
  (vec (.getBytes s)))



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

(defn- clean-space [s] (if (= s "SPACE") " " s))

(defn- load-reference-lists
  [s]
  (let [fl s
        digits (map bigdec (re-seq #"0\.[0-9]+" fl))
        letters (map #(apply short (clean-space %)) (re-seq #"[a-z]|SPACE" fl))
        ]
    ;; (vector letters digits)
    {:letters letters, :frequencies digits}
    ))

(defn format-reader-string
  "make a string representation of a list a clojure list for REPL"
  [s]
  (string/replace s "(" "'("))

(def raw-letters-file "./src/clojure_crypto_challenge/letters.csv")
(def letter-sequence-file "./src/clojure_crypto_challenge/letter-vectors.txt")

(defn create-letter-frequency-list-file
  "make a file with letter frequencies we can load directly into Repl.
  Only needed when the letter frequencies file changes."
  [in-file out-file]
  {:pre [(string? in-file)
         (.exists (io/file in-file))
         (string? out-file)]
   :post [(.exists (io/file out-file))]}
  (spit out-file (str (format-reader-string (load-reference-lists (slurp in-file))))))

;; (create-letter-frequency-list-file raw-letters-file letter-sequence-file)

(def english-frequency-map (load-string (slurp letter-sequence-file)))

(defn int-multiply
  [s v]
  (int (math/round (* s v))))

(defn- map-reference-lists
  [vs s]
  (zipmap (:letters vs)
          (map #(int-multiply s %) (:frequencies vs))))

(def memo-map-reference-lists
  (memoize map-reference-lists))


(defn to-ascii-letter
  [y]
  (let [x (short y)]
    (if (and (> x 0x1F) (< x 0x80))
      (bit-or x 0x20)
      0x00)))


(defn chi-distance [^double x ^double y]
  (let [nay (or (nil? y) (= y 0))]
    (if nay (math/expt x 2) (/ (math/expt (-  x y) 2) y))))


(def max-line-sample-length 28) ;number of chars to determine english

(defn letter-frequencies
  [c]
  (frequencies (map to-ascii-letter c)))

(defn reduce-map-values
  [f m]
  (reduce f (vals m)))

(defn line-score-as-fn
  "fn to score line as limited to line length. m is language frequency map,
  n is max length to score (for performance)"
  [m n]
  {:pre [(map? m)
         (number? n) (pos? n)]}
  (fn [x]
    (let [c (take n x)
          lm (memo-map-reference-lists m (count c))]
      (->>
       (letter-frequencies c)
       (merge-with chi-distance lm)
       (reduce-map-values +)))))


(defn score-line-as-english
  [x]
  ((line-score-as-fn english-frequency-map max-line-sample-length) x))


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
  (min-tupple 1 (get-XOR-score-table s)))

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
  {:pre [(seq? x)
         (seq? y)]
   :post [(number? %)]}
  (->>
   (fixed-XOR x y)
   (map bit-count)
   (reduce +)))

(defn get-keysize-edit-distance
  "get the mean keysize distance of k in the sequence
  of bytes ar. Do this n times. Returns a number"
  [k n ar]
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
                         [i (get-keysize-edit-distance i 4 code-phrase)]))))))

(defn block-sequence
  [source block-width]
  (for [k (range block-width)]
    (take-nth block-width (drop k source))))


(defn bytes->string
  [x]
  (String. (byte-array x)))




(defn break-repeat-XOR-cypher
  [code-phrase]
  (->>
   (get-keysizes code-phrase)
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

(defn- as-byte-array
  [s]
  {:pre [(or (string? s)
             (and  (sequential? s)
                   (every? number? s)))]}
  (byte-array (if (string? s) (.getBytes s) s)))


(defn aes-128-ecb-cipher-fn
  "doc-string"
  [md]
  (fn [ky ct]
    (let [k (SecretKeySpec. (as-byte-array ky) "AES")
          cipher (Cipher/getInstance "AES/ECB/NoPadding")]
      (.init cipher md k)
      (.doFinal cipher (as-byte-array ct)))))


(defn aes-128-ecb-decrypt
  "two strings, ky is key string, ct is cipher text. returns byte-array"
  [ky ct]
  (sequence ((aes-128-ecb-cipher-fn Cipher/DECRYPT_MODE) ky ct)))

;;; Set 1 Challenge 8 Detect AES-128-ECB

(defn- score-block-repetitions
  [n coll]
  )


(defn max-block-repetitions
  "Return fn to find most repetitions of an item in a seq"
  [coll]
  {:pre [(sequential? coll)]
   :post [(number? %)]}
  (apply max
         (vals
          (frequencies coll))))

(defn ratio-distinct
  "ratio of distinct items in a list. score > 1 shows repetitions"
  [coll]
  (/ (count coll) (count (distinct coll))))

(defn score-repetitions
  "Return mapping fn to return map of :score and :code.
  f is compare fn. n is block size"
  [f n]
  (fn [coll]
    {:post [(map? %)]}
    {:score (f (partition-all n coll)) :code coll}))


(defn detect-AES-ECB-code-text
  "AES ECB uses 16 Byte blocks. So if plain text has repeated
  16 byte blocks, the coded text will too"
  [x]
  {:pre [(seq? x)]
   :post [(seq? %)]}
  (reverse
   (sort-by :score
            (map (score-repetitions max-block-repetitions 16) x))))

;;; Set 2 Challenge 9

(defn- padded-partition
  [n p s]
  (partition n n (repeat p) s))

(defn padded-block
  "doc-string"
  [n p s]
  (first (padded-partition n p s)))

;;; Set 2 Challenge 10

(defn aes-128-ecb-encrypt
  "doc-string"
  [ky ct]
  (sequence ((aes-128-ecb-cipher-fn Cipher/ENCRYPT_MODE) ky ct)))

(defn cbc-encrypt
  ""
  [ky phrase iv]
  {:pre [ (= (count ky) 16)
         (sequential? phrase) (= (count phrase) 16)
         (sequential? iv) (= (count iv) 16)]
   :post [(sequential? %) (= (count %) 16)]}
  (aes-128-ecb-encrypt ky (fixed-XOR phrase iv)))

(defn zero-padded-16-byte-blocks
  "doc-string"
  [s]
  (padded-partition 16 0 s))

(defn- append-modified-fn
  [f]
  (fn [coll y] (conj coll (f y (peek coll)))))

(defn- chain-blocker-fn
  [f]
  (fn [blocked-phrase init-vec]
    (flatten
     (drop 1 (reduce (append-modified-fn f) [init-vec] blocked-phrase)))))


(defn aes-128-cbc-encipher
  "doc-string"
  [ky phrase iv]
  {:pre [(= (count ky) (count iv) 16)
         (sequential? iv)]
   :post [(>= (count %) 16)
          (zero? (mod (count %) 16))
          (>= (count %) (count phrase))
          (<= (count %) (+ (count phrase) 16))]}
  ((chain-blocker-fn (partial  cbc-encrypt ky))
   (zero-padded-16-byte-blocks phrase)  iv))

(defn zero-unpadded
  "return a padded enciphered text to its original state"
  [s]
  (string/replace s "\00" ""))

(defn aes-128-cbc-decipher
  "AES CBC is a 16 byte chained block cipher."
  [ky cipher iv]
  {:pre [(= (count ky) (count iv) 16)]
   :post [(= (count cipher) (count %))]}
  (fixed-XOR
   (aes-128-ecb-decrypt ky cipher)
   (into (seq cipher) (reverse iv)))) ;into conj's 1 at a time

(defn decoded-base64-file
  "carriage returns seem to break decode base64"
  [file]
  (decode-base64 (string/replace (slurp file) #"\r?\n" "")))

;;; Set 2 Challenge 11


(defn- rand-int-in-range
  [x y]
  {:pre [(< x y)]
   :post [(>= % x) (< % y)]}
  (rand-nth (range x y)))


(defn rand-byte-sequence
  ""
  ([n]
   (rand-byte-sequence n (inc n)))
  ([x y]
   (repeatedly (rand-int-in-range x y) #(rand-int 256))))



(defn- random-padded-sequence
  "as per challenge add 5 to 10 random bytes to plaintext"
  [coll]
  {:post [(<= (count coll) (+ (count coll) 11 11))]}
  (flatten
   (zero-padded-16-byte-blocks
    (concat
     (rand-byte-sequence 5 11)
     coll
     (rand-byte-sequence 5 11)))))


(defn randomly-encrypted-aes
  "doc-string"
  [f coll]
  (f
   (rand-byte-sequence 16)
   (random-padded-sequence coll)
   (rand-byte-sequence 16)))



(defn- aes-128-cbc-encipher-random-iv
  []
  (fn [ky phrase] (aes-128-cbc-encipher ky phrase (rand-byte-sequence 16))))

(defn encryption-oracle
  "randomly encrypt a sequence as either cbc or ecb adding random data to front and end"
  [coll]

  (let [f (rand-nth [(fn [x y & c] (aes-128-ecb-encrypt x y))
                     aes-128-cbc-encipher])]
    (randomly-encrypted-aes f coll)))


(defn ecb?
  "repeated blocks indicates an ecb encryption"
  [coll]
  (> (:score ((score-repetitions ratio-distinct 16) coll)) 1))

;;; Set 2 Challenge 12


(def random-16-byte-key (rand-byte-sequence 16))

(def challenge-12-unknown-text
  (decoded-base64-file "test/clojure_crypto_challenge/12.txt"))

(defn aes-128-ecb-oracle-hard-coded
  "Encrypt known text with hidden key. This is to allow practice of insertion attack."
  [coll]
  (vec (aes-128-ecb-encrypt
        random-16-byte-key
        (flatten (zero-padded-16-byte-blocks (into  coll challenge-12-unknown-text))))))

(defn- base-padded-vector
  [n coll]
  (let [i (inc (count coll))]
    (into (vec (repeat (- n i) 0)) coll)))

(defn- generate-message-sequence
  "we have known bytes in coll, this starts as nil
  we always generate total size as 1 less than n bytes
  we pad the rest so we can control the input to a cipher"
  ([n] (generate-message-sequence n nil))
  ([n coll]
   (map conj
        (repeat (base-padded-vector n coll))
        (range 256))))

(defn function-nil-size
  "assume that f is a message oracle"
  [f]
  (count (f nil)))

(defn limited-oracle-output
  ""
  [f]
  (fn [x]
    (take (function-nil-size f) (f x))))

(defn attempt-map
  "keyed map of attempts against message sequences"
  [f coll]
  (let [i (function-nil-size f)                           ;hardcode 144 as message length
        x (generate-message-sequence i coll)]
    (zipmap
     (map f x)
     x)))


(defn get-byte-from-message
  "doc-string"
  [f i]
  (vec ((limited-oracle-output f) (vec (repeat i 0)))))


(defn find-byte
  "Finding byte by manipulating last byte in a sequence.
  i is size of sequence. coll is the sequence of known bytes."
  [f coll]
  (let [x (inc (count coll))
        y (- (function-nil-size f) x)]                     ;hardcoded message size 144
    (vec (take-last x
                    (get
                     (attempt-map (limited-oracle-output f) coll)
                     (get-byte-from-message f y))))))

(defn ecb-decrypt-oracle
  "decrypt a block of"
  [f]
  (loop [coll nil
         i (function-nil-size f)]
    (if (zero? i)
      coll
      (recur (find-byte f coll) (dec i)))))


(crit/quick-bench (bytes->string (ecb-decrypt-oracle aes-128-ecb-oracle-hard-coded)))


(defn write-to-file [s coll]
  (with-open [w (clojure.java.io/writer s)]
    (doseq [x coll]
      (.write w (str x "\r\n")))))

;; (write-to-file "dave.txt" first-byte-sequences)
