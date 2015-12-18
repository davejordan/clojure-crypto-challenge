(defproject clojure-crypto-challenge "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [org.clojure/math.numeric-tower "0.0.4"]
                 [criterium "0.4.3"]]
  :main ^:skip-aot clojure-crypto-challenge.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}}
  :jvm-opts ["-Dcom.sun.management.jmxremote"
             "-Dcom.sun.management.jmxremote.ssl=false"
             "-Dcom.sun.management.jmxremote.authenticate=false"
             "-Dcom.sun.management.jmxremote.port=43210"]
  :repl-options {:init (set! *print-length* 50)}
  )
