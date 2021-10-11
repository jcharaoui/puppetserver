(ns puppetlabs.services.analytics.dropsonde
  (:require [clojure.java.shell :refer [sh]]
            [clojure.tools.logging :as log]
            [puppetlabs.i18n.core :as i18n]))

(def puppet-agent-ruby "/opt/puppetlabs/puppet/bin/ruby")
(def dropsonde-dir "/opt/puppetlabs/server/data/puppetserver/dropsonde")
(def dropsonde-bin (str dropsonde-dir "/bin/dropsonde"))

(defn run-dropsonde
  []
  (let [result (sh puppet-agent-ruby dropsonde-bin "submit"
                   :env {"GEM_HOME" dropsonde-dir
                         "GEM_PATH" dropsonde-dir
                         "HOME" dropsonde-dir})]
    (if (= 0 (:exit result))
      (log/info (i18n/trs "Successfully submitted module metrics via Dropsonde."))
      (log/warn (i18n/trs "Failed to submit module metrics via Dropsonde. Error: {0}"
                          (:err result))))))
