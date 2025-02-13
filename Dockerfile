FROM golang:1.23.4

#Set Working Directory
WORKDIR /usr/src/app

# Copy Env Configuration File
COPY .env ./

COPY . .

RUN make install \
  && make build

# Expose port
EXPOSE 8080

# Run application
CMD ["make", "start"]