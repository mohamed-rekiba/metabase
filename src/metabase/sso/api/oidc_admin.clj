(ns metabase.sso.api.oidc-admin
  "Superuser CRUD for OIDC providers at `/api/sso/oidc`."
  (:require
   [clojure.string :as str]
   [clojure.walk :as walk]
   [metabase.api.common :as api]
   [metabase.api.macros :as api.macros]
   [metabase.settings.core :as setting]
   [metabase.sso.core :as sso]
   [metabase.sso.oidc.util :as oidc.util]
   [metabase.sso.settings :as sso-settings]
   [metabase.util :as u]
   [metabase.util.i18n :refer [tru]]))

(set! *warn-on-reflection* true)

(def ^:private create-schema
  [:map {:closed true}
   [:key :string]
   [:login-prompt :string]
   [:issuer-uri :string]
   [:client-id :string]
   [:client-secret :string]
   [:scopes {:optional true} [:sequential :string]]
   [:enabled {:optional true} :boolean]
   [:attribute-map {:optional true} [:map-of :string :string]]
   [:group-sync {:optional true} [:map {:closed true}
                                  [:enabled {:optional true} :boolean]
                                  [:group-attribute {:optional true} :string]
                                  [:group-mappings {:optional true} [:map-of :string [:sequential :int]]]]]])

(def ^:private update-schema
  [:map {:closed true}
   [:login-prompt {:optional true} :string]
   [:issuer-uri {:optional true} :string]
   [:client-id {:optional true} :string]
   [:client-secret {:optional true} :string]
   [:scopes {:optional true} [:sequential :string]]
   [:enabled {:optional true} :boolean]
   [:attribute-map {:optional true} [:map-of :string :string]]
   [:group-sync {:optional true} [:map {:closed true}
                                  [:enabled {:optional true} :boolean]
                                  [:group-attribute {:optional true} :string]
                                  [:group-mappings {:optional true} [:map-of :string [:sequential :int]]]]]])

(def ^:private response-schema
  [:map {:closed true}
   [:key :string]
   [:login-prompt :string]
   [:issuer-uri :string]
   [:client-id :string]
   [:client-secret :string]
   [:scopes {:optional true} [:sequential :string]]
   [:enabled {:optional true} :boolean]
   [:attribute-map {:optional true} [:map-of :string :string]]
   [:group-sync {:optional true} [:map {:closed true}
                                  [:enabled {:optional true} :boolean]
                                  [:group-attribute {:optional true} :string]
                                  [:group-mappings {:optional true} [:map-of :string [:sequential :int]]]]]])

(defn- assert-not-env-locked!
  []
  (api/check-400 (not (oidc.util/env-configured?))
                 (tru "OIDC providers are configured via MB_OIDC_PROVIDERS and cannot be changed in the admin UI")))

(defn- sanitize-provider
  [provider]
  (cond-> provider
    (:client-secret provider) (update :client-secret setting/obfuscate-value)
    (:attribute-map provider) (update :attribute-map walk/stringify-keys)
    (get-in provider [:group-sync :group-mappings])
    (update-in [:group-sync :group-mappings] walk/stringify-keys)))

(defn- assert-connection-valid!
  [issuer-uri client-id client-secret]
  (let [result (sso/check-oidc-configuration issuer-uri client-id client-secret)]
    (api/check-400 (:ok result)
                   (or (get-in result [:credentials :error])
                       (get-in result [:discovery :error])
                       (tru "OIDC configuration check failed")))
    result))

(defn- merge-secret
  [existing body]
  (if (or (not (:client-secret body))
          (= (:client-secret body) (setting/obfuscate-value (:client-secret existing))))
    (dissoc body :client-secret)
    body))

(defn- provider-index
  [provider-key providers]
  (some (fn [[idx provider]]
          (when (= (oidc.util/provider-key provider) provider-key)
            idx))
        (map-indexed vector providers)))

;; GET /api/sso/oidc
(api.macros/defendpoint :get "/" :- [:sequential response-schema]
  "List configured OIDC providers."
  []
  (api/check-superuser)
  (mapv sanitize-provider (sso-settings/oidc-providers)))

;; GET /api/sso/oidc/:key
(api.macros/defendpoint :get "/:key" :- response-schema
  "Fetch a single OIDC provider."
  [{provider-key :key} :- [:map [:key :string]]]
  (api/check-superuser)
  (let [provider (sso-settings/get-oidc-provider provider-key)]
    (api/check-404 provider)
    (sanitize-provider provider)))

;; POST /api/sso/oidc
(api.macros/defendpoint :post "/" :- response-schema
  "Create an OIDC provider."
  [_route-params _query-params body :- create-schema]
  (api/check-superuser)
  (assert-not-env-locked!)
  (api/check-400 (u/valid-slug? (:key body))
                 (tru "Provider key must be a URL-safe slug (lowercase letters, numbers, hyphens)"))
  (api/check-400 (nil? (sso-settings/get-oidc-provider (:key body)))
                 (format "An OIDC provider with key '%s' already exists" (:key body)))
  (assert-connection-valid! (:issuer-uri body) (:client-id body) (:client-secret body))
  (let [provider (merge {:enabled false
                        :scopes ["openid" "email" "profile"]}
                       body)]
    (sso-settings/set-oidc-providers! (conj (vec (sso-settings/oidc-providers)) provider))
    (sanitize-provider provider)))

;; PUT /api/sso/oidc/:key
(api.macros/defendpoint :put "/:key" :- response-schema
  "Update an OIDC provider."
  [{provider-key :key} :- [:map [:key :string]]
   _query-params
   body :- update-schema]
  (api/check-superuser)
  (assert-not-env-locked!)
  (let [providers (vec (sso-settings/oidc-providers))
        idx       (provider-index provider-key providers)]
    (api/check-404 idx)
    (let [existing (nth providers idx)
          updated  (merge existing (merge-secret existing body))]
      (assert-connection-valid! (:issuer-uri updated) (:client-id updated) (:client-secret updated))
      (sso-settings/set-oidc-providers! (assoc providers idx updated))
      (sanitize-provider updated))))

(def ^:private check-request-schema
  [:map {:closed true}
   [:issuer-uri :string]
   [:client-id :string]
   [:client-secret {:optional true} [:maybe :string]]
   [:key {:optional true} [:maybe :string]]])

(def ^:private check-step-schema
  [:map
   [:step :keyword]
   [:success :boolean]
   [:verified {:optional true} :boolean]
   [:error {:optional true} :string]
   [:token-endpoint {:optional true} :string]])

(def ^:private check-response-schema
  [:map
   [:ok :boolean]
   [:discovery check-step-schema]
   [:credentials {:optional true} check-step-schema]])

;; POST /api/sso/oidc/check
(api.macros/defendpoint :post "/check" :- check-response-schema
  "Validate issuer discovery and client credentials."
  [_route-params _query-params body :- check-request-schema]
  (api/check-superuser)
  (let [client-secret (if (str/blank? (:client-secret body))
                        (when-let [key (:key body)]
                          (some-> (sso-settings/get-oidc-provider key) :client-secret))
                        (:client-secret body))]
    (assert-connection-valid! (:issuer-uri body) (:client-id body) client-secret)))

;; DELETE /api/sso/oidc/:key
(api.macros/defendpoint :delete "/:key" :- :nil
  "Delete an OIDC provider."
  [{provider-key :key} :- [:map [:key :string]]]
  (api/check-superuser)
  (assert-not-env-locked!)
  (let [providers (vec (sso-settings/oidc-providers))
        remaining (vec (remove #(= (oidc.util/provider-key %) provider-key) providers))]
    (when (= (count providers) (count remaining))
      (api/check-404 nil))
    (sso-settings/set-oidc-providers! remaining)
    nil))

(def ^{:arglists '([request respond raise])} routes
  "`/api/sso/oidc` routes."
  (api.macros/ns-handler *ns* api/+check-superuser))
