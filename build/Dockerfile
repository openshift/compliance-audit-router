ARG PROJECT="compliance-audit-router"
ARG PROJECT_DESCRIPTION="A daemon processing incoming SEIM alerts into cards in an issue-tracking system."
ARG BUILDER_IMAGE=registry.ci.openshift.org/openshift/release:golang-1.21

# BASE_IMAGE must be declared before the first FROM to be accesible in later build stages (eg: to use in second FROM)
ARG BASE_IMAGE=quay.io/app-sre/ubi9-ubi-minimal:9.6
ARG WORKDIR="/go/src/github.com/openshift/${PROJECT}"

# BUILDER IMAGE
FROM ${BUILDER_IMAGE} as builder

ARG WORKDIR
ADD . ${WORKDIR}
WORKDIR ${WORKDIR}

RUN git update-index --refresh; make CGO_ENABLED=0 build

# FINAL IMAGE
FROM $BASE_IMAGE

ARG PROJECT
ARG PROJECT_DESCRIPTION
ARG WORKDIR

LABEL vendor="RedHat" \
    name="openshift/${PROJECT}" \
    description="${PROJECT_DESCRIPTION}" \
    io.k8s.display-name="openshift/${PROJECT}" \
    io.k8s.description="${PROJECT_DESCIPTION}" \
    maintainer="RedHat <>" \
    org.label-schema.build-date="${BUILD_DATE}" \
    org.label-schema.description="${PROJECT_DESCIPTION}" \
    org.label-schema.name="openshift/${PROJECT}" \
    org.label-schema.vcs-url="https://github.com/openshift/${PROJECT}" \
    org.label-schema.vendor="openshift/${PROJECT}"

COPY --from=builder ${WORKDIR}/build/_output/${PROJECT} /bin/${PROJECT}
RUN ln -s /bin/${PROJECT} /bin/entrypoint

EXPOSE 8080/tcp

ENTRYPOINT ["/bin/entrypoint"]
