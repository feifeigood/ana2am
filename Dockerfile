FROM busybox

COPY bin/ana2am /bin/ana2am
RUN mkdir -p /ana2am

USER        nobody
WORKDIR     /ana2am
ENTRYPOINT [ "/bin/ana2am" ]
CMD        [ "" ]