# Demo sandbox image for Phase 4 dynamic verification of Python targets.
# The default sandbox image is python:3.12-slim with no outbound network, so
# targets whose dependencies are not vendored cannot start at verification
# time. Build this image once on the host (which has network access) and point
# the sandbox at it via mugiwara.yaml:
#
#   docker build -f docker/demo-sandbox.Dockerfile -t mugiwara-sandbox-py-demo:latest .
#
#   sandbox:
#     image: "mugiwara-sandbox-py-demo:latest"
FROM python:3.12-slim

# PyYAML 5.4.1 cannot build under Python 3.12 toolchains; the demo image only
# needs `import yaml` to resolve, so a wheel-available release is used.
RUN pip install --no-cache-dir Flask==2.3.2 "PyYAML>=6.0" requests==2.31.0
