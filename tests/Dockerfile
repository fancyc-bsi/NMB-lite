# Use the official Golang image to build the Go app
FROM golang:1.20 as builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY cmd cmd
COPY internal internal

# Build the Go app
RUN go build -o nmb cmd/main.go

# Start a new stage from scratch
FROM debian:bullseye-slim

# Install required packages
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/nmb /usr/local/bin/nmb

# Copy the test CSV file from the tests directory
COPY tests/test.csv /app/test.csv

# Set the Current Working Directory inside the container
WORKDIR /app

# Create the output directory
RUN mkdir -p /app/output

# Command to run the executable with t.csv and display the report
CMD ["sh", "-c", "nmb -nessus /app/test.csv && cat /app/output/NMB_scan_report.md"]
