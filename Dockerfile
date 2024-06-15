FROM ubuntu:22.04
LABEL maintainer="Daniel Moloney <daniel.moloney@wiz.io>"
LABEL description="Wiz Gadget - Lets Scan!"

# Set the working directory
WORKDIR /app

# Install the required packages
RUN apt update && apt install -y ca-certificates

# Copy the binary and the entrypoint script
COPY wiz-gadget ./
COPY docker-entrypoint.sh ./

# Set the entrypoint
ENTRYPOINT ["sh", "./docker-entrypoint.sh"]
