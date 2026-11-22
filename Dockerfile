FROM scratch
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/vault-plugin-secrets-gpg /vault-plugin-secrets-gpg
ENTRYPOINT ["/vault-plugin-secrets-gpg"]
