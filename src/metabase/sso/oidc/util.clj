(ns metabase.sso.oidc.util
  "Shared helpers for configured OIDC providers."
  (:require
   [clojure.string :as str]
   [metabase.api.common :as api]
   [metabase.appearance.core :as appearance]
   [metabase.sso.settings :as sso-settings]
   [metabase.system.core :as system]
   [metabase.util :as u]
   [metabase.util.i18n :refer [trs tru]]
   [metabase.util.log :as log])
  (:import
   (java.net URI URISyntaxException)))

(set! *warn-on-reflection* true)

(defn- relative-uri?
  [uri]
  (let [^URI parsed (if (string? uri)
                      (try
                        (URI. uri)
                        (catch URISyntaxException _
                          nil))
                      uri)]
    (or (nil? parsed)
        (and (nil? (.getHost parsed))
             (nil? (.getScheme parsed))))))

(defn validate-login-redirect!
  "Reject open redirects before starting an OIDC login flow."
  [redirect-url]
  (try
    (let [redirect (some-> redirect-url (URI.))
          site-host (some-> (system/site-url) (URI.) (.getHost))]
      (api/check-400 (or (nil? redirect-url)
                         (relative-uri? redirect)
                         (= (.getHost redirect) site-host)))
      redirect-url)
    (catch Exception e
      (log/error e "Invalid OIDC login redirect URL")
      (throw (ex-info (tru "Invalid redirect URL")
                      {:status-code  400
                       :redirect-url redirect-url})))))

(defn ensure-user-provisioning!
  "When automatic user provisioning is disabled, block login for unknown users."
  []
  (when-not (sso-settings/oidc-user-provisioning-enabled?)
    (throw (ex-info (trs "Sorry, but you''ll need a {0} account to view this page. Please contact your administrator."
                         (u/slugify (appearance/site-name)))
                    {:status-code 401}))))

(defn resolve-mapped-group-ids
  "Map IdP group names from a token claim to Metabase group IDs."
  [group-names group-mappings]
  (->> (cond-> group-names (string? group-names) vector)
       (map keyword)
       (mapcat group-mappings)
       set))

(defn all-mapped-group-ids
  "Every Metabase group ID referenced in `group-mappings`."
  [group-mappings]
  (-> group-mappings vals flatten set))

(defn provider-field
  [provider field]
  (let [kw (keyword field)]
    (or (get provider kw) (get provider (name kw)) (get provider field))))

(defn provider-key
  [provider]
  (some-> (provider-field provider :key) str))

(defn provider-enabled?
  [provider]
  (boolean (provider-field provider :enabled)))

(defn attribute-claim
  [attribute-map claim]
  (when attribute-map
    (or (get attribute-map claim)
        (get attribute-map (name claim))
        (get attribute-map (keyword claim)))))

(defn runtime-config
  "Build the runtime OIDC options passed to the base :provider/oidc implementation."
  [provider request]
  (when (and (provider-field provider :client-id)
             (provider-field provider :client-secret)
             (provider-field provider :issuer-uri))
    (let [attrs (or (provider-field provider :attribute-map) {})]
      (cond-> {:client-id     (provider-field provider :client-id)
               :client-secret (provider-field provider :client-secret)
               :issuer-uri    (provider-field provider :issuer-uri)
               :scopes        (or (provider-field provider :scopes)
                                  ["openid" "email" "profile"])
               :redirect-uri  (:redirect-uri request)}
        (attribute-claim attrs :email)
        (assoc :attribute-email (attribute-claim attrs :email))

        (attribute-claim attrs :first_name)
        (assoc :attribute-firstname (attribute-claim attrs :first_name))

        (attribute-claim attrs :last_name)
        (assoc :attribute-lastname (attribute-claim attrs :last_name))))))

(defn env-configured?
  "True when MB_OIDC_PROVIDERS is set in the environment."
  []
  (boolean (not (str/blank? (System/getenv "MB_OIDC_PROVIDERS")))))
