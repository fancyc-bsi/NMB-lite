# Use the official Golang image to build the Go app
FROM golang:1.20-bullseye as builder

# Set CGO_ENABLED=0 for static compilation
ENV CGO_ENABLED=0

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the source code
COPY cmd cmd
COPY internal internal

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Build the Go app with static linking
RUN go build -ldflags="-w -s" -o nmb cmd/main.go

# Use Alpine for the final image
FROM alpine:3.18

# Install required packages
RUN apk add --no-cache nmap curl

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/nmb /usr/local/bin/nmb

# Copy the test CSV file
COPY tests/test.csv /app/test.csv

# Set the Working Directory
WORKDIR /app

# Create the output directory
RUN mkdir -p /app/output

# Command to run the executable
CMD ["sh", "-c", "nmb -nessus /app/test.csv && cat /app/output/NMB_scan_report.md"]