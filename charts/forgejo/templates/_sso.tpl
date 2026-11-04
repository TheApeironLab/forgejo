{{- define "code.ssoEnv" -}}
- name: SSO_TENANT
  value: {{ required "auth.oidc.tenant is required" .Values.auth.oidc.tenant | quote }}
- {name: GITEA____APP_NAME, value: Code}
- {name: GITEA____RUN_USER, value: git}
- {name: HOME, value: /data/git}
- {name: GITEA__database__DB_TYPE, value: postgres}
- name: GITEA__database__HOST
  value: {{ .Values.postgresHost | quote }}
- {name: GITEA__database__NAME, value: git}
- {name: GITEA__database__USER, value: git}
- name: GITEA__database__PASSWD
  valueFrom: {secretKeyRef: {name: git-db, key: password}}
- {name: GITEA__security__INSTALL_LOCK, value: "true"}
- {name: GITEA__service__DISABLE_REGISTRATION, value: "true"}
- {name: GITEA__oauth2_client__ENABLE_AUTO_REGISTRATION, value: "false"}
- {name: GITEA__oauth2_client__ACCOUNT_LINKING, value: disabled}
- {name: GITEA__server__OFFLINE_MODE, value: "true"}
- {name: GITEA__server__DISABLE_SSH, value: "true"}
- {name: GITEA__repository__ROOT, value: /data/git/repositories}
- {name: SSL_CERT_DIR, value: "/etc/ssl/certs:/etc/chentu-ca"}
{{- end -}}

{{- define "code.ssoMounts" -}}
- {name: git-data, mountPath: /data}
- {name: chentu-ca, mountPath: /etc/chentu-ca, readOnly: true}
- {name: oidc-credentials, mountPath: /run/sso/oidc, readOnly: true}
- {name: directory-credentials, mountPath: /run/sso/directory, readOnly: true}
- {name: admin-credentials, mountPath: /run/sso/admin, readOnly: true}
{{- end -}}
