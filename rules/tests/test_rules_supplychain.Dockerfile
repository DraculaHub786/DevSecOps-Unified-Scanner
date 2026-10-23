# Test fixture for Dockerfile supply chain rules
# ruleid: org-supplychain-docker-latest-tag
FROM ubuntu:latest

# ruleid: org-supplychain-curl-pipe-sh
RUN curl -fsSL https://example.com/install.sh | bash
