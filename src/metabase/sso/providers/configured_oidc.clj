(ns metabase.sso.providers.configured-oidc
  "OIDC login backed by the `oidc-providers` setting (admin UI or MB_OIDC_PROVIDERS)."
  (:require
   [clojure.string :as str]
   [metabase.auth-identity.core :as auth-identity]
   [metabase.sso.core :as sso]
   [metabase.sso.oidc.util :as oidc.util]
   [metabase.sso.settings :as sso-settings]
   [metabase.util.i18n :refer [tru]]
   [methodical.core :as methodical]))

(set! *warn-on-reflection* true)

(derive :provider/configured-oidc :provider/oidc)

(methodical/defmethod auth-identity/authenticate :provider/configured-oidc
  [_provider request]
  (cond
    (not (sso-settings/oidc-enabled))
    {:success? false
     :error :oidc-not-enabled
     :message (tru "OIDC authentication is not enabled")}

    (str/blank? (some-> (:oidc-provider-key request) str))
    {:success? false
     :error :missing-provider
     :message (tru "OIDC provider key is required")}

    :else
    (let [provider-key (:oidc-provider-key request)
          provider     (sso-settings/get-oidc-provider provider-key)]
      (cond
        (nil? provider)
        {:success? false
         :error :provider-not-found
         :message (tru "OIDC provider ''{0}'' not found" provider-key)}

        (not (oidc.util/provider-enabled? provider))
        {:success? false
         :error :provider-not-enabled
         :message (tru "OIDC provider ''{0}'' is not enabled" provider-key)}

        :else
        (if-let [runtime (oidc.util/runtime-config provider request)]
          (let [result (next-method _provider (assoc request :oidc-config runtime))]
            (if (and (:success? result) (:user-data result))
              (assoc-in result [:user-data :sso_source] :oidc)
              result))
          {:success? false
           :error :configuration-error
           :message (tru "Failed to build OIDC configuration for provider ''{0}''" provider-key)})))))

(methodical/defmethod auth-identity/login! :provider/configured-oidc
  [provider {:keys [user] :as request}]
  (when-not user
    (oidc.util/ensure-user-provisioning!))
  (next-method provider request))

(methodical/defmethod auth-identity/login! :after :provider/configured-oidc
  [_provider {:keys [oidc-provider-key user claims] :as result}]
  (when-let [provider (sso-settings/get-oidc-provider oidc-provider-key)]
    (when-let [group-sync (oidc.util/provider-field provider :group-sync)]
      (when (oidc.util/provider-field group-sync :enabled)
        (let [group-attribute (oidc.util/provider-field group-sync :group-attribute)
              group-mappings  (oidc.util/provider-field group-sync :group-mappings)
              user-groups     (when (and claims group-attribute)
                                (or (get claims (keyword group-attribute))
                                    (get claims group-attribute)))]
          (when (and user-groups group-mappings user)
            (let [groups-to-sync (if (sequential? user-groups) user-groups [user-groups])]
              (if (empty? group-mappings)
                (sso/sync-group-memberships! user
                                             (oidc.util/resolve-mapped-group-ids groups-to-sync group-mappings))
                (sso/sync-group-memberships! user
                                             (oidc.util/resolve-mapped-group-ids groups-to-sync group-mappings)
                                             (oidc.util/all-mapped-group-ids group-mappings)))))))))
  result)
