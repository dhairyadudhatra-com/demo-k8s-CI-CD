# Use the official Node.js image as the base image
FROM node:lts-bullseye-slim

# Set the working directory in the container
WORKDIR /app

# Copy the package.json and package-lock.json files
COPY package*.json ./

# Install the application dependencies
RUN npm install

# Install netcat
RUN apt-get update && apt-get install -y netcat

# Copy the rest of the application code
COPY . .

#Exec Permission
RUN chmod +x wait-for-it.sh

# Set the command to start the application
CMD ["./wait-for-it.sh", "node", "index.js"]
