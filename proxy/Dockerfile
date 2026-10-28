ARG CRS_IMAGE
FROM ${CRS_IMAGE}
# ASSUMPTIONS TO VERIFY: base image entrypoint is /docker-entrypoint.sh and the process user can
# write the shared volume. Adjust USER/paths if your pinned tag differs.
COPY agent.sh entrypoint.sh /cg/
USER root
RUN chmod +x /cg/agent.sh /cg/entrypoint.sh && mkdir -p /etc/cyberguard/agent && chown -R 10002:10002 /etc/cyberguard
ENTRYPOINT ["/cg/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
